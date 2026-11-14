import type { Env } from '../types.ts';
import { SECURITY_HEADERS } from './security.middleware.ts';

export function resolveCorsOrigin(request: Request, env: Env): string | null {
  const origin = request.headers.get('Origin');
  if (!origin) return null;

  // Same-origin POST/fetch (e.g., behind Cloudflared Tunnel or Cloudflare Pages)
  try {
    const reqOrigin = new URL(request.url).origin;
    if (origin === reqOrigin) return origin;
  } catch {
    // ignore malformed URL
  }

  const configured = env.ALLOWED_ORIGIN || 'https://detector360.app';
  if (origin === configured) return origin;

  // Permit local Edge dev & Cloudflared Quick Tunnels / Cloudflare Pages previews
  if (
    origin.startsWith('http://localhost:') ||
    origin.startsWith('http://127.0.0.1:') ||
    origin.endsWith('.trycloudflare.com') ||
    origin.endsWith('.pages.dev')
  ) {
    return origin;
  }

  return null;
}

export function handleCorsPreflight(request: Request, env: Env): Response | null {
  if (request.method !== 'OPTIONS') return null;

  const allowedOrigin = resolveCorsOrigin(request, env);
  const headers = new Headers({
    ...SECURITY_HEADERS,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'Access-Control-Max-Age': '86400',
  });

  if (allowedOrigin) {
    headers.set('Access-Control-Allow-Origin', allowedOrigin);
    headers.set('Access-Control-Allow-Credentials', 'true');
    headers.set('Vary', 'Origin');
  }

  return new Response(null, { status: 204, headers });
}

export function withCors(response: Response, request: Request, env: Env): Response {
  const allowedOrigin = resolveCorsOrigin(request, env);
  if (!allowedOrigin) return response;

  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', allowedOrigin);
  headers.set('Access-Control-Allow-Credentials', 'true');
  headers.set('Vary', 'Origin');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
