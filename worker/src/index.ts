import type { Env, ExecutionContext, RequestContext } from './types.ts';
import { ApiRouter } from './router.ts';
import { handleCorsPreflight, withCors } from './middlewares/cors.middleware.ts';
import { applySecurityHeaders, jsonResponse } from './middlewares/security.middleware.ts';
import { resolveOptionalUser } from './middlewares/auth.middleware.ts';

const router = new ApiRouter();

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const preflight = handleCorsPreflight(request, env);
    if (preflight) return preflight;

    try {
      const clientIp =
        request.headers.get('CF-Connecting-IP') ||
        request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
        '127.0.0.1';

      const user = await resolveOptionalUser(request, env);

      const rc: RequestContext = {
        request,
        env,
        ctx,
        params: {},
        clientIp,
        user,
      };

      const response = await router.dispatch(rc);
      return withCors(applySecurityHeaders(response), request, env);
    } catch (error) {
      console.error('[Detector360 Worker Unhandled Error]:', error);
      const errRes = jsonResponse(
        {
          success: false,
          error: {
            code: 'INTERNAL_EDGE_ERROR',
            message: 'Ocurrió un inconveniente temporal en el motor de análisis. Intenta nuevamente.',
          },
        },
        500
      );
      return withCors(errRes, request, env);
    }
  },
};
