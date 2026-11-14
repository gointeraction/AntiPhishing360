export interface ApiErrorShape {
  code: string;
  message: string;
  details?: Record<string, string>;
  retry_after_seconds?: number;
}

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly details?: Record<string, string>;
  public readonly retryAfterSeconds?: number;

  constructor(
    statusCode: number,
    code: string,
    message: string,
    details?: Record<string, string>,
    retryAfterSeconds?: number
  ) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export function jsonResponse(
  body: Record<string, unknown>,
  status = 200,
  extraHeaders?: HeadersInit
): Response {
  const headers = new Headers(extraHeaders);
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  return new Response(JSON.stringify(body), { status, headers });
}

export function errorResponse(
  status: number,
  code: string,
  message: string,
  details?: Record<string, string>,
  retryAfterSeconds?: number,
  extraHeaders?: HeadersInit
): Response {
  const errorObj: ApiErrorShape = { code, message };
  if (details && Object.keys(details).length > 0) {
    errorObj.details = details;
  }
  if (typeof retryAfterSeconds === 'number') {
    errorObj.retry_after_seconds = retryAfterSeconds;
  }

  const headers = new Headers(extraHeaders);
  if (typeof retryAfterSeconds === 'number') {
    headers.set('Retry-After', String(retryAfterSeconds));
  }

  return jsonResponse({ success: false, error: errorObj }, status, headers);
}

export async function parseJsonBody<T = Record<string, unknown>>(
  request: Request,
  maxBytes = 32_768
): Promise<T> {
  const contentType = request.headers.get('content-type') || '';
  if (!contentType.toLowerCase().includes('application/json')) {
    throw new AppError(
      415,
      'UNSUPPORTED_MEDIA_TYPE',
      'El cuerpo de la petición debe enviarse en formato application/json'
    );
  }

  const rawText = await request.text();
  if (rawText.length > maxBytes) {
    throw new AppError(
      413,
      'PAYLOAD_TOO_LARGE',
      'El tamaño de la petición excede el límite permitido'
    );
  }

  try {
    const parsed = JSON.parse(rawText) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Invalid JSON object');
    }
    return parsed as T;
  } catch {
    throw new AppError(400, 'INVALID_JSON', 'El cuerpo JSON proporcionado tiene formato inválido');
  }
}
