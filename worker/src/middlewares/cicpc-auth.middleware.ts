import type { CicpcOfficer, CicpcOfficerRole, Env } from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { getJwtSecret, parseCookies } from './auth.middleware.ts';

export function getCicpcJwtSecret(env: Env): string {
  return `${getJwtSecret(env)}::CICPC_DIDI_RESTRICTED_AUTHORITY_V1`;
}

export function buildCicpcAuthCookie(request: Request, token: string): string[] {
  const isHttps = new URL(request.url).protocol === 'https:';
  const cookieName = isHttps ? '__Host-d360_cicpc_session' : 'd360_cicpc_session';
  const secureAttr = isHttps ? '; Secure' : '';

  return [
    `${cookieName}=${encodeURIComponent(token)}; HttpOnly${secureAttr}; SameSite=Strict; Path=/; Max-Age=7200`,
  ];
}

export function buildClearCicpcAuthCookie(request: Request): string[] {
  const isHttps = new URL(request.url).protocol === 'https:';
  const cookieName = isHttps ? '__Host-d360_cicpc_session' : 'd360_cicpc_session';
  const secureAttr = isHttps ? '; Secure' : '';

  return [`${cookieName}=; HttpOnly${secureAttr}; SameSite=Strict; Path=/; Max-Age=0`];
}

export async function resolveCicpcOfficer(
  request: Request,
  env: Env
): Promise<CicpcOfficer | null> {
  const cookies = parseCookies(request.headers.get('Cookie'));
  let token =
    cookies['__Host-d360_cicpc_session'] || cookies['d360_cicpc_session'] || '';

  if (!token) {
    const authHeader = request.headers.get('X-CICPC-Token') || request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    } else if (authHeader && request.headers.has('X-CICPC-Token')) {
      token = authHeader.trim();
    }
  }

  if (!token) return null;

  const payload = await CryptoService.verifyJwt<{
    sub: string;
    badge_id: string;
    full_name: string;
    rank_title: string;
    role: CicpcOfficerRole;
    scope: string;
  }>(token, getCicpcJwtSecret(env));

  if (!payload || payload.scope !== 'CICPC_DIDI_OFFICER' || !payload.badge_id) {
    return null;
  }

  return {
    id: payload.sub,
    badge_id: payload.badge_id,
    full_name: payload.full_name,
    rank_title: payload.rank_title,
    role: payload.role,
  };
}
