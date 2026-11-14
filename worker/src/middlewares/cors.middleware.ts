import { Env } from '../types/env';
import { errorResponse } from '../utils/response';

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function getAllowedOrigins(env: Env): Set<string> {
  const raw = env.ALLOWED_ORIGIN || '';
  const origins = raw
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  return new Set(origins);
}

export function isOriginAllowed(origin: string | null, requestUrl: string, env: Env): boolean {
  if (!origin) {
    return true;
  }
  const allowed = getAllowedOrigins(env);
  if (allowed.has(origin)) {
    return true;
  }
  try {
    const reqOrigin = new URL(requestUrl).origin;
    return origin === reqOrigin;
  } catch {
    return false;
  }
}

export function handleCorsPreflight(request: Request, env: Env): Response | null {
  if (request.method !== 'OPTIONS') {
    return null;
  }

  const origin = request.headers.get('Origin');
  if (!origin || !isOriginAllowed(origin, request.url, env)) {
    return errorResponse(403, 'CORS_ORIGIN_FORBIDDEN', 'El origen de la solicitud no está autorizado');
  }

  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Requested-With',
      'Access-Control-Max-Age': '86400',
      Vary: 'Origin'
    }
  });
}

/**
 * Validates Origin and custom CSRF header X-Requested-With on state-changing endpoints.
 */
export function verifyCsrfAndOrigin(request: Request, env: Env): Response | null {
  const origin = request.headers.get('Origin');

  if (origin && !isOriginAllowed(origin, request.url, env)) {
    return errorResponse(403, 'CORS_ORIGIN_FORBIDDEN', 'Origen cruzado no permitido por política de seguridad');
  }

  if (MUTATING_METHODS.has(request.method.toUpperCase())) {
    const xRequestedWith = request.headers.get('X-Requested-With');
    if (xRequestedWith !== 'Detector360-PWA') {
      return errorResponse(
        403,
        'CSRF_PROTECTION_REJECTED',
        'Falta o es inválida la cabecera de verificación anti-CSRF (X-Requested-With)'
      );
    }
  }

  return null;
}

export function attachCorsHeaders(response: Response, request: Request, env: Env): Response {
  const origin = request.headers.get('Origin');
  if (!origin || !isOriginAllowed(origin, request.url, env)) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Credentials', 'true');
  headers.set('Vary', 'Origin');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
