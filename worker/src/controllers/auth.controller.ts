import type { RequestContext } from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { UserRepository } from '../repositories/user.repository.ts';
import { jsonResponse } from '../middlewares/security.middleware.ts';
import { RateLimitMiddleware } from '../middlewares/rateLimit.middleware.ts';
import {
  buildAuthCookies,
  buildClearAuthCookies,
  getJwtSecret,
  parseCookies,
} from '../middlewares/auth.middleware.ts';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export class AuthController {
  static async register(rc: RequestContext): Promise<Response> {
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'auth_register',
      identifier: rc.clientIp,
      maxRequests: 10,
      windowSeconds: 60,
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_JSON', message: 'El formato de los datos enviados no es válido.' },
        },
        400
      );
    }

    const alias = typeof body.alias === 'string' ? body.alias.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const pendingScanId =
      typeof body.pending_scan_id === 'string' ? body.pending_scan_id.trim() : '';

    if (alias.length < 2 || alias.length > 50) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_ALIAS',
            message: 'Por favor ingresa un nombre o alias de entre 2 y 50 caracteres.',
          },
        },
        400
      );
    }

    if (!EMAIL_REGEX.test(email)) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_EMAIL',
            message: 'Por favor ingresa un correo electrónico válido.',
          },
        },
        400
      );
    }

    if (password.length < 8) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'WEAK_PASSWORD',
            message: 'La contraseña debe tener al menos 8 caracteres para proteger tu cuenta.',
          },
        },
        400
      );
    }

    const userRepo = new UserRepository(rc.env.DB);
    const existing = await userRepo.findByEmail(email);
    if (existing) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'EMAIL_ALREADY_REGISTERED',
            message: 'Este correo electrónico ya tiene una cuenta activa en Detector360',
          },
        },
        400
      );
    }

    const userId = CryptoService.generateUlid('usr');
    const passwordHash = await CryptoService.hashPassword(password);
    const newUser = await userRepo.createUser({
      id: userId,
      alias,
      email,
      passwordHash,
      planTier: 'citizen_free',
    });

    let linkedScan = false;
    if (pendingScanId && pendingScanId.startsWith('scn_')) {
      linkedScan = await userRepo.claimAnonymousScan(pendingScanId, userId);
    }

    const secret = getJwtSecret(rc.env);
    const accessToken = await CryptoService.signJwt(
      {
        sub: newUser.id,
        alias: newUser.alias,
        email: newUser.email,
        plan_tier: newUser.plan_tier,
        iss: rc.env.JWT_ISSUER || 'detector360.app',
      },
      secret,
      900
    );

    const refreshToken = CryptoService.generateRandomToken(32);
    const refreshHash = await CryptoService.sha256Hex(refreshToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      .toISOString()
      .replace(/\.\d{3}Z$/, 'Z');

    await userRepo.saveRefreshToken({
      id: CryptoService.generateUlid('rtk'),
      userId: newUser.id,
      tokenHash: refreshHash,
      userAgent: rc.request.headers.get('User-Agent') || 'unknown',
      expiresAt,
    });

    const cookies = buildAuthCookies(rc.request, accessToken, refreshToken);

    return jsonResponse(
      {
        success: true,
        message: linkedScan
          ? 'Cuenta creada exitosamente. Tu análisis previo ha sido guardado en tu historial.'
          : 'Cuenta ciudadana creada exitosamente. Tu escudo personal está activo.',
        data: {
          user: newUser,
          linked_scan_id: linkedScan ? pendingScanId : null,
        },
      },
      201,
      { 'Set-Cookie': cookies }
    );
  }

  static async login(rc: RequestContext): Promise<Response> {
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'auth_login',
      identifier: rc.clientIp,
      maxRequests: 15,
      windowSeconds: 60,
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_JSON', message: 'El formato de los datos enviados no es válido.' },
        },
        400
      );
    }

    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const pendingScanId =
      typeof body.pending_scan_id === 'string' ? body.pending_scan_id.trim() : '';

    if (!email || !password) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'MISSING_CREDENTIALS',
            message: 'Ingresa tu correo electrónico y contraseña.',
          },
        },
        400
      );
    }

    const userRepo = new UserRepository(rc.env.DB);
    const userRow = await userRepo.findByEmail(email);

    if (!userRow || userRow.is_active !== 1) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'El correo electrónico o la contraseña no coinciden',
          },
        },
        401
      );
    }

    const validPassword = await CryptoService.verifyPassword(password, userRow.password_hash);
    if (!validPassword) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'El correo electrónico o la contraseña no coinciden',
          },
        },
        401
      );
    }

    if (pendingScanId && pendingScanId.startsWith('scn_')) {
      await userRepo.claimAnonymousScan(pendingScanId, userRow.id);
    }

    const secret = getJwtSecret(rc.env);
    const accessToken = await CryptoService.signJwt(
      {
        sub: userRow.id,
        alias: userRow.alias,
        email: userRow.email,
        plan_tier: userRow.plan_tier,
        iss: rc.env.JWT_ISSUER || 'detector360.app',
      },
      secret,
      900
    );

    const refreshToken = CryptoService.generateRandomToken(32);
    const refreshHash = await CryptoService.sha256Hex(refreshToken);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      .toISOString()
      .replace(/\.\d{3}Z$/, 'Z');

    await userRepo.saveRefreshToken({
      id: CryptoService.generateUlid('rtk'),
      userId: userRow.id,
      tokenHash: refreshHash,
      userAgent: rc.request.headers.get('User-Agent') || 'unknown',
      expiresAt,
    });

    const cookies = buildAuthCookies(rc.request, accessToken, refreshToken);

    return jsonResponse(
      {
        success: true,
        message: 'Bienvenido nuevamente a Detector360',
        data: {
          user: {
            id: userRow.id,
            alias: userRow.alias,
            email: userRow.email,
            plan_tier: userRow.plan_tier,
          },
          expires_in: 900,
        },
      },
      200,
      { 'Set-Cookie': cookies }
    );
  }

  static async logout(rc: RequestContext): Promise<Response> {
    const cookies = parseCookies(rc.request.headers.get('Cookie'));
    const refreshRaw = cookies['__Host-d360_refresh'] || cookies['d360_refresh'] || '';
    if (refreshRaw) {
      const refreshHash = await CryptoService.sha256Hex(refreshRaw);
      const userRepo = new UserRepository(rc.env.DB);
      await userRepo.revokeRefreshTokenByHash(refreshHash);
    }

    const clearCookies = buildClearAuthCookies(rc.request);
    return jsonResponse(
      {
        success: true,
        message: 'Sesión cerrada de forma segura',
      },
      200,
      { 'Set-Cookie': clearCookies }
    );
  }

  static async me(rc: RequestContext): Promise<Response> {
    if (!rc.user) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'UNAUTHORIZED', message: 'No hay una sesión ciudadana activa.' },
        },
        401
      );
    }

    return jsonResponse({
      success: true,
      data: { user: rc.user },
    });
  }
}
