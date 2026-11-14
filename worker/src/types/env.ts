export interface Env {
  DB: D1Database;
  KV_CACHE: KVNamespace;
  R2_EVIDENCE: R2Bucket;
  JWT_SECRET: string;
  ALLOWED_ORIGIN: string;
  ENVIRONMENT?: string;
}

export interface AuthenticatedUser {
  id: string;
  alias: string;
  email: string;
}

export interface RequestContext {
  requestId: string;
  clientIp: string;
  user: AuthenticatedUser | null;
  params: Record<string, string>;
  isSecureOrigin: boolean;
}

export type RouteHandler = (
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  reqCtx: RequestContext
) => Promise<Response>;
