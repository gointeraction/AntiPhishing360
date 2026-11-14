import type { AuthUser, Env, PlanTier } from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { UserRepository } from '../repositories/user.repository.ts';

const DEFAULT_DEV_JWT_SECRET =
  'd360_edge_quantum_shield_hmac_256_secret_key_change_in_wrangler_secret';

export function getJwtSecret(env: Env): string {
  return env.JWT_SECRET || DEFAULT_DEV_JWT_SECRET;
}

export function parseCookies(cookieHeader: string | null): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    cookies[key] = decodeURIComponent(val);
  }
  return cookies;
}

export function buildAuthCookies(
  request: Request,
  accessToken: string,
  refreshToken: string
): string[] {
  const isHttps = new URL(request.url).protocol === 'https:';
  const accessName = isHttps ? '__Host-d360_access' : 'd360_access';
  const refreshName = isHttps ? '__Host-d360_refresh' : 'd360_refresh';
  const secureAttr = isHttps ? '; Secure' : '';

  return [
    `${accessName}=${encodeURIComponent(accessToken)}; HttpOnly${secureAttr}; SameSite=Strict; Path=/; Max-Age=900`,
    `${refreshName}=${encodeURIComponent(refreshToken)}; HttpOnly${secureAttr}; SameSite=Strict; Path=/; Max-Age=604800`,
  ];
}

export function buildClearAuthCookies(request: Request): string[] {
  const isHttps = new URL(request.url).protocol === 'https:';
  const accessName = isHttps ? '__Host-d360_access' : 'd360_access';
  const refreshName = isHttps ? '__Host-d360_refresh' : 'd360_refresh';
  const secureAttr = isHttps ? '; Secure' : '';

  return [
    `${accessName}=; HttpOnly${secureAttr}; SameSite=Strict; Path=/; Max-Age=0`,
    `${refreshName}=; HttpOnly${secureAttr}; SameSite=Strict; Path=/; Max-Age=0`,
  ];
}

export async function resolveOptionalUser(
  request: Request,
  env: Env
): Promise<AuthUser | null> {
  const cookies = parseCookies(request.headers.get('Cookie'));
  let token = cookies['__Host-d360_access'] || cookies['d360_access'] || '';

  if (!token) {
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    }
  }

  const secret = getJwtSecret(env);

  if (token) {
    const payload = await CryptoService.verifyJwt<{
      sub: string;
      alias: string;
      email: string;
      plan_tier: PlanTier;
    }>(token, secret);

    if (payload && payload.sub) {
      return {
        id: payload.sub,
        alias: payload.alias,
        email: payload.email,
        plan_tier: payload.plan_tier,
      };
    }
  }

  // Fallback check via valid refresh token if access cookie expired
  const refreshRaw = cookies['__Host-d360_refresh'] || cookies['d360_refresh'] || '';
  if (refreshRaw) {
    const refreshHash = await CryptoService.sha256Hex(refreshRaw);
    const userRepo = new UserRepository(env.DB);
    const validSession = await userRepo.findValidRefreshToken(refreshHash);
    if (validSession) {
      return await userRepo.findById(validSession.user_id);
    }
  }

  return null;
}
