import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import workerEntrypoint from './worker/src/index.ts';
import type {
  D1Database,
  D1PreparedStatement,
  Env,
  ExecutionContext,
  KVNamespace,
  R2Bucket,
} from './worker/src/types.ts';
import { SECURITY_HEADERS } from './worker/src/middlewares/security.middleware.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, '.local-edge');
const R2_DIR = path.join(DATA_DIR, 'r2');
const DB_PATH = path.join(DATA_DIR, 'detector360.sqlite');
const FRONTEND_DIR = path.join(__dirname, 'frontend');
const MIGRATIONS_DIR = path.join(__dirname, 'worker', 'migrations');

fs.mkdirSync(R2_DIR, { recursive: true });

// ----------------------------------------------------------------------------
// 1. Local Cloudflare D1 Adapter (node:sqlite DatabaseSync)
// ----------------------------------------------------------------------------
class LocalD1Statement implements D1PreparedStatement {
  private boundValues: unknown[] = [];
  private readonly sqlite: DatabaseSync;
  private readonly sql: string;

  constructor(sqlite: DatabaseSync, sql: string) {
    this.sqlite = sqlite;
    this.sql = sql;
  }

  bind(...values: unknown[]): D1PreparedStatement {
    const clone = new LocalD1Statement(this.sqlite, this.sql);
    clone.boundValues = values.map((v) => (v === undefined ? null : v));
    return clone;
  }

  async first<T = Record<string, unknown>>(colName?: string): Promise<T | null> {
    const stmt = this.sqlite.prepare(this.sql);
    const row = stmt.get(...(this.boundValues as never[])) as Record<string, unknown> | undefined;
    if (!row) return null;
    if (colName) return ((row[colName] as T) ?? null);
    return row as T;
  }

  async run(): Promise<{ success: boolean; meta?: Record<string, unknown> }> {
    const stmt = this.sqlite.prepare(this.sql);
    const res = stmt.run(...(this.boundValues as never[]));
    return {
      success: true,
      meta: { changes: Number(res.changes), last_row_id: Number(res.lastInsertRowid) },
    };
  }

  async all<T = Record<string, unknown>>(): Promise<{ results: T[]; success: boolean }> {
    const stmt = this.sqlite.prepare(this.sql);
    const rows = stmt.all(...(this.boundValues as never[])) as T[];
    return { results: rows, success: true };
  }
}

export class LocalD1Database implements D1Database {
  public readonly sqlite: DatabaseSync;

  constructor(dbFilePath: string) {
    this.sqlite = new DatabaseSync(dbFilePath);
    this.sqlite.exec('PRAGMA foreign_keys = ON;');
  }

  prepare(query: string): D1PreparedStatement {
    return new LocalD1Statement(this.sqlite, query);
  }

  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<T[]> {
    const out: T[] = [];
    this.sqlite.exec('BEGIN TRANSACTION;');
    try {
      for (const st of statements) {
        const res = await st.run();
        out.push(res as T);
      }
      this.sqlite.exec('COMMIT;');
    } catch (err) {
      this.sqlite.exec('ROLLBACK;');
      throw err;
    }
    return out;
  }

  async exec(query: string): Promise<{ count: number; duration: number }> {
    const start = Date.now();
    this.sqlite.exec(query);
    return { count: 1, duration: Date.now() - start };
  }
}

// ----------------------------------------------------------------------------
// 2. Local Cloudflare KV Adapter (In-Memory with TTL)
// ----------------------------------------------------------------------------
export class LocalKVNamespace implements KVNamespace {
  private store = new Map<string, { value: string; expiresAt: number | null }>();

  async get(key: string, type?: 'text'): Promise<string | null>;
  async get<T = unknown>(key: string, type: 'json'): Promise<T | null>;
  async get<T = unknown>(key: string, type: 'text' | 'json' = 'text'): Promise<string | T | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    if (type === 'json') {
      try {
        return JSON.parse(entry.value) as T;
      } catch {
        return null;
      }
    }
    return entry.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    const expiresAt = options?.expirationTtl ? Date.now() + options.expirationTtl * 1000 : null;
    this.store.set(key, { value, expiresAt });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

// ----------------------------------------------------------------------------
// 3. Local Cloudflare R2 Adapter (Filesystem Object Bucket)
// ----------------------------------------------------------------------------
export class LocalR2Bucket implements R2Bucket {
  private readonly baseDir: string;

  constructor(baseDir: string) {
    this.baseDir = baseDir;
    fs.mkdirSync(this.baseDir, { recursive: true });
  }

  async put(key: string, value: string | ArrayBuffer | Uint8Array): Promise<unknown> {
    const safeRel = key.replace(/[^a-zA-Z0-9._/-]/g, '_');
    const fullPath = path.join(this.baseDir, safeRel);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    if (typeof value === 'string') {
      fs.writeFileSync(fullPath, value, 'utf-8');
    } else if (value instanceof Uint8Array) {
      fs.writeFileSync(fullPath, value);
    } else {
      fs.writeFileSync(fullPath, new Uint8Array(value));
    }
    return { key: safeRel };
  }

  async get(key: string): Promise<{ text(): Promise<string> } | null> {
    const safeRel = key.replace(/[^a-zA-Z0-9._/-]/g, '_');
    const fullPath = path.join(this.baseDir, safeRel);
    if (!fs.existsSync(fullPath)) return null;
    return {
      async text() {
        return fs.readFileSync(fullPath, 'utf-8');
      },
    };
  }
}

export function createEdgeEnv(customDbPath?: string): Env {
  const db = new LocalD1Database(customDbPath || DB_PATH);

  const migrationFiles = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  for (const file of migrationFiles) {
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf-8');
    db.sqlite.exec(sql);
  }

  return {
    DB: db,
    KV_CACHE: new LocalKVNamespace(),
    R2_EVIDENCE: new LocalR2Bucket(R2_DIR),
    JWT_SECRET: process.env.JWT_SECRET || 'd360_local_edge_quantum_secret_2026',
    JWT_ISSUER: 'detector360.app',
    CICPC_MASTER_KEY: process.env.CICPC_MASTER_KEY || 'DIDI-360-CLAVE-SEGURIDAD-2026',
    ALLOWED_ORIGIN: 'http://localhost:8788',
    ENVIRONMENT: 'development',
  };
}

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.ico': 'image/x-icon',
};

export async function handleEdgeRequest(
  webReq: Request,
  env: Env,
  ctx?: ExecutionContext
): Promise<Response> {
  const execCtx: ExecutionContext = ctx || {
    waitUntil: (p) => {
      p.catch((e) => console.error('[waitUntil error]', e));
    },
    passThroughOnException: () => {},
  };

  const fullUrl = new URL(webReq.url);

  if (fullUrl.pathname.startsWith('/api/')) {
    return await workerEntrypoint.fetch(webReq, env, execCtx);
  }

  // Serve Cloudflare Pages static frontend + clean routes (_redirects)
  const pathname = decodeURIComponent(fullUrl.pathname);
  let filePath = '';

  if (pathname === '/' || pathname === '/index.html') {
    filePath = path.join(FRONTEND_DIR, 'index.html');
  } else if (pathname === '/login') {
    filePath = path.join(FRONTEND_DIR, 'login.html');
  } else if (pathname === '/register') {
    filePath = path.join(FRONTEND_DIR, 'register.html');
  } else if (pathname === '/dashboard') {
    filePath = path.join(FRONTEND_DIR, 'dashboard.html');
  } else if (pathname === '/scan/new') {
    filePath = path.join(FRONTEND_DIR, 'scan-new.html');
  } else if (/^\/scan\/[^/]+\/?$/.test(pathname)) {
    filePath = path.join(FRONTEND_DIR, 'scan.html');
  } else if (pathname === '/cicpc' || pathname === '/cicpc/') {
    filePath = path.join(FRONTEND_DIR, 'cicpc.html');
  } else if (pathname === '/cicpc/login' || pathname === '/cicpc/login/') {
    filePath = path.join(FRONTEND_DIR, 'cicpc-login.html');
  } else {
    const candidate = path.normalize(path.join(FRONTEND_DIR, pathname));
    if (
      candidate.startsWith(FRONTEND_DIR) &&
      fs.existsSync(candidate) &&
      fs.statSync(candidate).isFile()
    ) {
      filePath = candidate;
    }
  }

  if (!filePath || !fs.existsSync(filePath)) {
    return new Response('404 - Recurso no encontrado en Detector360', {
      status: 404,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }

  const ext = path.extname(filePath).toLowerCase();
  const mimeType = MIME_TYPES[ext] || 'application/octet-stream';
  const stat = fs.statSync(filePath);
  const totalSize = stat.size;

  // Support HTTP Byte-Range Requests (206 Partial Content) for smooth widescreen video streaming
  const rangeHeader = webReq.headers.get('range');
  if (rangeHeader && rangeHeader.startsWith('bytes=') && totalSize > 0) {
    const parts = rangeHeader.replace(/bytes=/, '').split('-');
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? Math.min(parseInt(parts[1], 10), totalSize - 1) : totalSize - 1;

    if (!Number.isNaN(start) && start >= 0 && start <= end && end < totalSize) {
      const chunkLength = end - start + 1;
      const chunkBuf = Buffer.alloc(chunkLength);
      const fd = fs.openSync(filePath, 'r');
      try {
        fs.readSync(fd, chunkBuf, 0, chunkLength, start);
      } finally {
        fs.closeSync(fd);
      }

      return new Response(chunkBuf, {
        status: 206,
        headers: {
          'Content-Type': mimeType,
          'Accept-Ranges': 'bytes',
          'Content-Range': `bytes ${start}-${end}/${totalSize}`,
          'Content-Length': String(chunkLength),
          ...SECURITY_HEADERS,
        },
      });
    }
  }

  const content = fs.readFileSync(filePath);
  return new Response(content, {
    status: 200,
    headers: {
      'Content-Type': mimeType,
      'Accept-Ranges': 'bytes',
      'Content-Length': String(totalSize),
      ...SECURITY_HEADERS,
    },
  });
}

export function createDetector360HttpServer(env: Env) {
  return http.createServer(async (req, res) => {
    try {
      const host = req.headers.host || 'localhost:8788';
      const xfProto = req.headers['x-forwarded-proto'];
      const protoHeader = Array.isArray(xfProto) ? xfProto[0] : xfProto;
      const proto = protoHeader?.split(',')[0]?.trim() === 'https' ? 'https' : 'http';
      const fullUrl = new URL(req.url || '/', `${proto}://${host}`);

      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      const rawBody = Buffer.concat(chunks);

      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (Array.isArray(v)) {
          v.forEach((item) => headers.append(k, item));
        } else if (typeof v === 'string') {
          headers.set(k, v);
        }
      }
      if (!headers.has('CF-Connecting-IP')) {
        headers.set('CF-Connecting-IP', req.socket.remoteAddress || '127.0.0.1');
      }

      const webReq = new Request(fullUrl.toString(), {
        method: req.method || 'GET',
        headers,
        body:
          req.method !== 'GET' && req.method !== 'HEAD' && rawBody.length > 0
            ? rawBody
            : undefined,
      });

      const edgeRes = await handleEdgeRequest(webReq, env);
      res.statusCode = edgeRes.status;

      const setCookies =
        typeof (edgeRes.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie ===
        'function'
          ? (edgeRes.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
          : [];

      edgeRes.headers.forEach((val, key) => {
        if (key.toLowerCase() === 'set-cookie') return;
        res.setHeader(key, val);
      });
      if (setCookies.length > 0) {
        res.setHeader('Set-Cookie', setCookies);
      }

      const resBuf = Buffer.from(await edgeRes.arrayBuffer());
      res.end(resBuf);
    } catch (err) {
      console.error('[DevServer Error]:', err);
      res.statusCode = 500;
      res.end('Internal Edge Simulator Error');
    }
  });
}

// Start server when invoked directly
if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const port = parseInt(process.env.PORT || '8788', 10);
  const env = createEdgeEnv();
  const server = createDetector360HttpServer(env);
  server.listen(port, '127.0.0.1', () => {
    console.log(`\n🛡️  Detector360 Edge Platform (Cloudflare Pages + Worker + D1 + KV + R2)`);
    console.log(`⚡ Servidor activo en: http://localhost:${port}`);
    console.log(`🔬 API Forense REST:  http://localhost:${port}/api/v1/health\n`);
  });
}
