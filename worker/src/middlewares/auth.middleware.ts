import { CryptoService } from '../services/crypto.service';
import { AuthenticatedUser, Env, RequestContext } from '../types/env';
import { errorResponse } from '../utils/response';

const PROD_ACCESS_COOKIE = '__Host-d360_access';
const PROD_REFRESH_COOKIE = '__Host-d360_refresh';
const DEV_ACCESS_COOKIE = 'd360_access';
const DEV_REFRESH_COOKIE = 'd360_refresh';

export function isLocalhostHttp(requestUrl: string): boolean {
  try {
    const parsed = new URL(requestUrl);
    return (
      parsed.protocol === 'http:' &&
      (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')
    );
  } catch {
    return false;
  }
}

export function parseCookies(cookieHeader: string | null): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) {
    return cookies;
  }

  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) continue;
    const key = pair.slice(0, eqIdx).trim();
    const val = pair.slice(eqIdx + 1).trim();
    if (key) {
      cookies[key] = decodeURIComponent(val);
    }
  }
  return cookies;
}

export function extractAccessCookie(request: Request): string | null {
  const cookies = parseCookies(request.headers.get('Cookie'));
  if (cookies[PROD_ACCESS_COOKIE]) {
    return cookies[PROD_ACCESS_COOKIE]!;
  }
  if (isLocalhostHttp(request.url) && cookies[DEV_ACCESS_COOKIE]) {
    return cookies[DEV_ACCESS_COOKIE]!;
  }
  return null;
}

export function extractRefreshCookie(request: Request): string | null {
  const cookies = parseCookies(request.headers.get('Cookie'));
  if (cookies[PROD_REFRESH_COOKIE]) {
    return cookies[PROD_REFRESH_COOKIE]!;
  }
  if (isLocalhostHttp(request.url) && cookies[DEV_REFRESH_COOKIE]) {
    return cookies[DEV_REFRESH_COOKIE]!;
  }
  return null;
}

export function buildAuthCookies(
  accessToken: string,
  refreshToken: string,
  isSecureOrigin: boolean,
  accessMaxAge = 900,
  refreshMaxAge = 604_800
): string[] {
  const accessName = isSecureOrigin ? PROD_ACCESS_COOKIE : DEV_ACCESS_COOKIE;
  const refreshName = isSecureOrigin ? PROD_REFRESH_COOKIE : DEV_REFRESH_COOKIE;
  const secureFlag = isSecureOrigin ? '; Secure' : '';

  return [
    `${accessName}=${encodeURIComponent(accessToken)}; HttpOnly${secureFlag}; SameSite=Strict; Path=/; Max-Age=${accessMaxAge}`,
    `${refreshName}=${encodeURIComponent(refreshToken)}; HttpOnly${secureFlag}; SameSite=Strict; Path=/; Max-Age=${refreshMaxAge}`
  ];
}

export function buildAccessCookieOnly(
  accessToken: string,
  isSecureOrigin: boolean,
  accessMaxAge = 900
): string {
  const accessName = isSecureOrigin ? PROD_ACCESS_COOKIE : DEV_ACCESS_COOKIE;
  const secureFlag = isSecureOrigin ? '; Secure' : '';
  return `${accessName}=${encodeURIComponent(accessToken)}; HttpOnly${secureFlag}; SameSite=Strict; Path=/; Max-Age=${accessMaxAge}`;
}

export function buildClearAuthCookies(isSecureOrigin: boolean): string[] {
  const accessName = isSecureOrigin ? PROD_ACCESS_COOKIE : DEV_ACCESS_COOKIE;
  const refreshName = isSecureOrigin ? PROD_REFRESH_COOKIE : DEV_REFRESH_COOKIE;
  const secureFlag = isSecureOrigin ? '; Secure' : '';

  return [
    `${accessName}=; HttpOnly${secureFlag}; SameSite=Strict; Path=/; Max-Age=0`,
    `${refreshName}=; HttpOnly${secureFlag}; SameSite=Strict; Path=/; Max-Age=0`
  ];
}

export async function authenticateRequest(
  request: Request,
  env: Env,
  reqCtx: RequestContext,
  mode: 'optional' | 'required'
): Promise<Response | null> {
  const token = extractAccessCookie(request);
  if (!token) {
    if (mode === 'required') {
      return errorResponse(
        401,
        'UNAUTHORIZED',
        'Debes iniciar sesión para acceder a este recurso'
      );
    }
    return null;
  }

  const payload = await CryptoService.verifyAccessToken(token, env.JWT_SECRET);
  if (!payload) {
    if (mode === 'required') {
      return errorResponse(
        401,
        'UNAUTHORIZED',
        'Tu sesión ha expirado o el token de acceso no es válido'
      );
    }
    return null;
  }

  const authenticatedUser: AuthenticatedUser = {
    id: payload.sub,
    alias: payload.alias,
    email: payload.email
  };
  reqCtx.user = authenticatedUser;
  return null;
}
