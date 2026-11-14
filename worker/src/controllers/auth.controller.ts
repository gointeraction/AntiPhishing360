import {
  authenticateRequest,
  buildAuthCookies,
  buildClearAuthCookies,
  extractRefreshCookie
} from '../middlewares/auth.middleware';
import { enforceRateLimit } from '../middlewares/rateLimit.middleware';
import { UserRepository } from '../repositories/user.repository';
import { CryptoService } from '../services/crypto.service';
import { Env, RequestContext } from '../types/env';
import { AppError, errorResponse, jsonResponse, parseJsonBody } from '../utils/response';
import { generateUlid } from '../utils/ulid';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const ACCESS_TTL_SECONDS = 900; // 15 minutes
const REFRESH_TTL_SECONDS = 7 * 24 * 3600; // 7 days

// Dummy hash used to equalize response time when email does not exist (anti-enumeration)
const DUMMY_PBKDF2_HASH =
  '$pbkdf2-sha512$210000$00112233445566778899aabbccddeeff$' + 'a'.repeat(128);

function validatePasswordStrength(password: string): string | null {
  if (password.length < 10 || password.length > 128) {
    return 'La contraseña debe tener entre 10 y 128 caracteres';
  }
  if (!/[A-Z]/.test(password)) {
    return 'La contraseña debe incluir al menos una letra mayúscula';
  }
  if (!/[a-z]/.test(password)) {
    return 'La contraseña debe incluir al menos una letra minúscula';
  }
  if (!/[0-9]/.test(password)) {
    return 'La contraseña debe incluir al menos un número';
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'La contraseña debe incluir al menos un símbolo especial';
  }
  return null;
}

function appendSetCookies(response: Response, setCookieValues: string[]): Response {
  const headers = new Headers(response.headers);
  for (const cookie of setCookieValues) {
    headers.append('Set-Cookie', cookie);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

export class AuthController {
  static async register(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const rateLimited = await enforceRateLimit(env, reqCtx, 'auth');
    if (rateLimited) return rateLimited;

    const body = await parseJsonBody<{
      alias?: unknown;
      email?: unknown;
      password?: unknown;
    }>(request);

    const alias = typeof body.alias === 'string' ? body.alias.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    const details: Record<string, string> = {};
    if (alias.length < 2 || alias.length > 50 || !/^[a-zA-ZÀ-ÿ0-9_.\-\s]+$/.test(alias)) {
      details.alias = 'El alias debe tener entre 2 y 50 caracteres alfanuméricos válidos';
    }
    if (!EMAIL_REGEX.test(email) || email.length > 160) {
      details.email = 'El formato del correo electrónico no es válido';
    }
    const pwdIssue = validatePasswordStrength(password);
    if (pwdIssue) {
      details.password = pwdIssue;
    }

    if (Object.keys(details).length > 0) {
      return errorResponse(
        400,
        'VALIDATION_ERROR',
        'Los datos proporcionados no cumplen los requisitos de seguridad',
        details
      );
    }

    const existing = await UserRepository.findByEmail(env.DB, email);
    if (existing) {
      return errorResponse(
        400,
        'VALIDATION_ERROR',
        'Los datos proporcionados no cumplen los requisitos de seguridad',
        { email: 'El correo electrónico ya se encuentra registrado' }
      );
    }

    const userId = generateUlid('usr');
    const passwordHash = await CryptoService.hashPassword(password);
    const createdUser = await UserRepository.createUser(env.DB, {
      id: userId,
      alias,
      email,
      passwordHash
    });

    // Issue initial session cookies immediately upon registration (User Story 6.1)
    const accessToken = await CryptoService.signAccessToken(
      { id: createdUser.id, alias: createdUser.alias, email: createdUser.email },
      env.JWT_SECRET,
      ACCESS_TTL_SECONDS
    );
    const rawRefreshToken = CryptoService.generateOpaqueToken(32);
    const refreshTokenHash = await CryptoService.sha256Hex(rawRefreshToken);
    const refreshExpiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000)
      .toISOString()
      .replace(/\.\d{3}Z$/, 'Z');

    await UserRepository.saveRefreshToken(env.DB, {
      id: generateUlid('rtk'),
      userId: createdUser.id,
      tokenHash: refreshTokenHash,
      userAgent: request.headers.get('User-Agent'),
      expiresAt: refreshExpiresAt
    });

    const cookies = buildAuthCookies(
      accessToken,
      rawRefreshToken,
      reqCtx.isSecureOrigin,
      ACCESS_TTL_SECONDS,
      REFRESH_TTL_SECONDS
    );

    const res = jsonResponse(
      {
        success: true,
        message: 'Cuenta ciudadana creada exitosamente',
        data: {
          user: createdUser,
          session: { expires_in: ACCESS_TTL_SECONDS }
        }
      },
      201
    );

    return appendSetCookies(res, cookies);
  }

  static async login(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const rateLimited = await enforceRateLimit(env, reqCtx, 'auth');
    if (rateLimited) return rateLimited;

    const body = await parseJsonBody<{
      email?: unknown;
      password?: unknown;
      remember_me?: unknown;
    }>(request);

    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const rememberMe = body.remember_me !== false;

    if (!email || !password) {
      return errorResponse(401, 'INVALID_CREDENTIALS', 'Correo electrónico o contraseña incorrectos');
    }

    const user = await UserRepository.findByEmail(env.DB, email);
    if (!user || user.is_active !== 1) {
      await CryptoService.verifyPassword(password, DUMMY_PBKDF2_HASH);
      return errorResponse(401, 'INVALID_CREDENTIALS', 'Correo electrónico o contraseña incorrectos');
    }

    const validPassword = await CryptoService.verifyPassword(password, user.password_hash);
    if (!validPassword) {
      return errorResponse(401, 'INVALID_CREDENTIALS', 'Correo electrónico o contraseña incorrectos');
    }

    const refreshTtl = rememberMe ? REFRESH_TTL_SECONDS : 86_400;
    const accessToken = await CryptoService.signAccessToken(
      { id: user.id, alias: user.alias, email: user.email },
      env.JWT_SECRET,
      ACCESS_TTL_SECONDS
    );
    const rawRefreshToken = CryptoService.generateOpaqueToken(32);
    const refreshTokenHash = await CryptoService.sha256Hex(rawRefreshToken);
    const refreshExpiresAt = new Date(Date.now() + refreshTtl * 1000)
      .toISOString()
      .replace(/\.\d{3}Z$/, 'Z');

    await UserRepository.saveRefreshToken(env.DB, {
      id: generateUlid('rtk'),
      userId: user.id,
      tokenHash: refreshTokenHash,
      userAgent: request.headers.get('User-Agent'),
      expiresAt: refreshExpiresAt
    });

    const cookies = buildAuthCookies(
      accessToken,
      rawRefreshToken,
      reqCtx.isSecureOrigin,
      ACCESS_TTL_SECONDS,
      refreshTtl
    );

    const res = jsonResponse({
      success: true,
      message: 'Sesión iniciada correctamente',
      data: {
        user: {
          id: user.id,
          alias: user.alias,
          email: user.email
        },
        session: {
          expires_in: ACCESS_TTL_SECONDS
        }
      }
    });

    return appendSetCookies(res, cookies);
  }

  static async refresh(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const rawRefresh = extractRefreshCookie(request);
    if (!rawRefresh) {
      throw new AppError(
        401,
        'REFRESH_TOKEN_INVALID',
        'La sesión ha expirado o fue revocada. Inicie sesión nuevamente'
      );
    }

    const currentHash = await CryptoService.sha256Hex(rawRefresh);
    const tokenRecord = await UserRepository.findValidRefreshToken(env.DB, currentHash);
    if (!tokenRecord) {
      const clear = buildClearAuthCookies(reqCtx.isSecureOrigin);
      return appendSetCookies(
        errorResponse(
          401,
          'REFRESH_TOKEN_INVALID',
          'La sesión ha expirado o fue revocada. Inicie sesión nuevamente'
        ),
        clear
      );
    }

    const user = await UserRepository.findById(env.DB, tokenRecord.user_id);
    if (!user) {
      await UserRepository.revokeRefreshTokenByHash(env.DB, currentHash);
      const clear = buildClearAuthCookies(reqCtx.isSecureOrigin);
      return appendSetCookies(
        errorResponse(
          401,
          'REFRESH_TOKEN_INVALID',
          'La cuenta asociada a la sesión ya no se encuentra activa'
        ),
        clear
      );
    }

    // Automatic refresh token rotation on every refresh call
    const nextRawRefresh = CryptoService.generateOpaqueToken(32);
    const nextRefreshHash = await CryptoService.sha256Hex(nextRawRefresh);
    const nextExpiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000)
      .toISOString()
      .replace(/\.\d{3}Z$/, 'Z');

    await UserRepository.rotateRefreshToken(env.DB, tokenRecord.id, {
      id: generateUlid('rtk'),
      userId: user.id,
      tokenHash: nextRefreshHash,
      userAgent: request.headers.get('User-Agent'),
      expiresAt: nextExpiresAt
    });

    const nextAccessToken = await CryptoService.signAccessToken(
      { id: user.id, alias: user.alias, email: user.email },
      env.JWT_SECRET,
      ACCESS_TTL_SECONDS
    );

    const cookies = buildAuthCookies(
      nextAccessToken,
      nextRawRefresh,
      reqCtx.isSecureOrigin,
      ACCESS_TTL_SECONDS,
      REFRESH_TTL_SECONDS
    );

    return appendSetCookies(
      jsonResponse({
        success: true,
        data: {
          expires_in: ACCESS_TTL_SECONDS,
          user: {
            id: user.id,
            alias: user.alias,
            email: user.email
          }
        }
      }),
      cookies
    );
  }

  static async logout(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const rawRefresh = extractRefreshCookie(request);
    if (rawRefresh) {
      const hash = await CryptoService.sha256Hex(rawRefresh);
      await UserRepository.revokeRefreshTokenByHash(env.DB, hash);
    }

    const clearCookies = buildClearAuthCookies(reqCtx.isSecureOrigin);
    return appendSetCookies(
      jsonResponse({
        success: true,
        message: 'Sesión cerrada y tokens revocados'
      }),
      clearCookies
    );
  }

  static async me(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const authErr = await authenticateRequest(request, env, reqCtx, 'required');
    if (authErr) return authErr;

    return jsonResponse({
      success: true,
      data: {
        user: reqCtx.user
      }
    });
  }
}
