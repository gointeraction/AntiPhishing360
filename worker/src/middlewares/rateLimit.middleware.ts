import type { KVNamespace } from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { jsonResponse } from './security.middleware.ts';

export class RateLimitMiddleware {
  static async enforce(params: {
    kv: KVNamespace;
    bucketName: string;
    identifier: string;
    maxRequests: number;
    windowSeconds: number;
    friendlyMessage?: string;
  }): Promise<Response | null> {
    const idHash = (await CryptoService.sha256Hex(params.identifier)).slice(0, 24);
    const windowSlot = Math.floor(Date.now() / (params.windowSeconds * 1000));
    const key = `rl:${params.bucketName}:${idHash}:${windowSlot}`;

    const raw = await params.kv.get(key, 'text');
    const current = raw ? parseInt(raw, 10) : 0;

    if (current >= params.maxRequests) {
      const elapsedInWindow = Math.floor((Date.now() / 1000) % params.windowSeconds);
      const retryAfter = Math.max(5, params.windowSeconds - elapsedInWindow);

      return jsonResponse(
        {
          success: false,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message:
              params.friendlyMessage ||
              `Has realizado muchas solicitudes seguidas. Espera ${retryAfter} segundos para continuar.`,
            retry_after_seconds: retryAfter,
          },
        },
        429,
        { 'Retry-After': String(retryAfter) }
      );
    }

    await params.kv.put(key, String(current + 1), {
      expirationTtl: Math.max(60, params.windowSeconds + 10),
    });

    return null;
  }
}
