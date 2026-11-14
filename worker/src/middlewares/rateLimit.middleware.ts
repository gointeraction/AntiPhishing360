import { Env, RequestContext } from '../types/env';
import { errorResponse } from '../utils/response';

export type RateLimitProfile = 'scan' | 'auth' | 'community_write';

interface WindowRule {
  windowSeconds: number;
  maxRequests: number;
  label: string;
}

function getRules(profile: RateLimitProfile, isAuthenticated: boolean): WindowRule[] {
  switch (profile) {
    case 'auth':
      return [{ windowSeconds: 900, maxRequests: 5, label: '5 intentos cada 15 minutos' }];
    case 'community_write':
      return [{ windowSeconds: 3600, maxRequests: 15, label: '15 reportes por hora' }];
    case 'scan':
    default:
      if (isAuthenticated) {
        return [
          { windowSeconds: 60, maxRequests: 40, label: '40 análisis por minuto' },
          { windowSeconds: 3600, maxRequests: 500, label: '500 análisis por hora' }
        ];
      }
      return [
        { windowSeconds: 60, maxRequests: 15, label: '15 análisis por minuto' },
        { windowSeconds: 3600, maxRequests: 100, label: '100 análisis por hora' }
      ];
  }
}

export async function enforceRateLimit(
  env: Env,
  reqCtx: RequestContext,
  profile: RateLimitProfile
): Promise<Response | null> {
  if (!env.KV_CACHE) {
    return null;
  }

  const isAuthenticated = Boolean(reqCtx.user);
  const subject = reqCtx.user ? `usr_${reqCtx.user.id}` : `ip_${reqCtx.clientIp}`;
  const rules = getRules(profile, isAuthenticated);
  const nowSeconds = Math.floor(Date.now() / 1000);

  for (const rule of rules) {
    const bucketIndex = Math.floor(nowSeconds / rule.windowSeconds);
    const retryAfter = rule.windowSeconds - (nowSeconds % rule.windowSeconds);
    const kvKey = `rl:${profile}:${rule.windowSeconds}:${subject}:${bucketIndex}`;

    try {
      const currentRaw = await env.KV_CACHE.get(kvKey);
      const currentCount = currentRaw ? Number.parseInt(currentRaw, 10) || 0 : 0;

      if (currentCount >= rule.maxRequests) {
        return errorResponse(
          429,
          'RATE_LIMIT_EXCEEDED',
          `Has alcanzado el límite de ${rule.label}. Intenta nuevamente en ${retryAfter} segundos.`,
          undefined,
          retryAfter
        );
      }

      // KV minimum expirationTtl is 60 seconds
      const ttl = Math.max(60, rule.windowSeconds + 10);
      await env.KV_CACHE.put(kvKey, String(currentCount + 1), { expirationTtl: ttl });
    } catch {
      // Fail-open only on transient KV storage errors so legitimate citizens aren't locked out
      return null;
    }
  }

  return null;
}
