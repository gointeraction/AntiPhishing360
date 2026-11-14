import { AuthController } from './controllers/auth.controller';
import { CommunityController } from './controllers/community.controller';
import { ScanController } from './controllers/scan.controller';
import { isLocalhostHttp } from './middlewares/auth.middleware';
import {
  attachCorsHeaders,
  handleCorsPreflight,
  verifyCsrfAndOrigin
} from './middlewares/cors.middleware';
import { applySecurityHeaders } from './middlewares/security.middleware';
import { Router } from './router';
import { Env, RequestContext } from './types/env';
import { AppError, errorResponse, jsonResponse } from './utils/response';
import { generateUlid } from './utils/ulid';

const router = new Router();

// Health Check Endpoint
router.get('/api/v1/health', async () => {
  return jsonResponse({
    success: true,
    data: {
      service: 'detector360-api',
      status: 'operational',
      timestamp: new Date().toISOString()
    }
  });
});

// Module 1: Authentication & Session Management
router.post('/api/v1/auth/register', AuthController.register);
router.post('/api/v1/auth/login', AuthController.login);
router.post('/api/v1/auth/refresh', AuthController.refresh);
router.post('/api/v1/auth/logout', AuthController.logout);
router.get('/api/v1/auth/me', AuthController.me);

// Module 2: Forensic Engine & URL Scans
// Static `/history` registered BEFORE `:scan_id` to prevent route shadowing
router.post('/api/v1/scans', ScanController.createScan);
router.get('/api/v1/scans/history', ScanController.getUserHistory);
router.get('/api/v1/scans/:scan_id', ScanController.getScanById);
router.delete('/api/v1/scans/:scan_id', ScanController.deleteUserScan);

// Module 3: Citizen Community Alerts
router.post('/api/v1/community/alerts', CommunityController.publishAlert);
router.get('/api/v1/community/alerts', (req, env) => CommunityController.listPublicAlerts(req, env));

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestId = generateUlid('req');
    const clientIp =
      request.headers.get('CF-Connecting-IP') ||
      request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
      '127.0.0.1';

    // 1. Handle CORS Preflight
    const preflightResponse = handleCorsPreflight(request, env);
    if (preflightResponse) {
      return applySecurityHeaders(preflightResponse, requestId);
    }

    // 2. Enforce Origin & CSRF protection
    const csrfBlocked = verifyCsrfAndOrigin(request, env);
    if (csrfBlocked) {
      return applySecurityHeaders(attachCorsHeaders(csrfBlocked, request, env), requestId);
    }

    let response: Response;
    try {
      const url = new URL(request.url);
      const matched = router.match(request.method, url.pathname);

      if (!matched) {
        response = errorResponse(
          404,
          'ROUTE_NOT_FOUND',
          `La ruta solicitada (${request.method} ${url.pathname}) no existe en Detector360 API`
        );
      } else {
        const reqCtx: RequestContext = {
          requestId,
          clientIp,
          user: null,
          params: matched.params,
          isSecureOrigin: !isLocalhostHttp(request.url)
        };

        response = await matched.handler(request, env, ctx, reqCtx);
      }
    } catch (err) {
      if (err instanceof AppError) {
        response = errorResponse(
          err.statusCode,
          err.code,
          err.message,
          err.details,
          err.retryAfterSeconds
        );
      } else {
        // Never leak internal stack traces or DB internals to external clients
        console.error(`[Detector360 Error][${requestId}]`, err);
        response = errorResponse(
          500,
          'INTERNAL_SERVER_ERROR',
          'Ocurrió un error interno procesando la auditoría. Ningún dato sensible fue expuesto.'
        );
      }
    }

    const withCors = attachCorsHeaders(response, request, env);
    return applySecurityHeaders(withCors, requestId);
  }
};
