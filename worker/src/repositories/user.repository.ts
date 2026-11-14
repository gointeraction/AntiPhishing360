import { RefreshTokenRecord, UserRecord } from '../types/models';

export class UserRepository {
  static async findByEmail(db: D1Database, email: string): Promise<UserRecord | null> {
    const normalized = email.trim().toLowerCase();
    const row = await db
      .prepare(
        `SELECT id, alias, email, password_hash, is_active, created_at, updated_at
         FROM users
         WHERE email = ?
         LIMIT 1`
      )
      .bind(normalized)
      .first<UserRecord>();

    return row ?? null;
  }

  static async findById(db: D1Database, id: string): Promise<UserRecord | null> {
    const row = await db
      .prepare(
        `SELECT id, alias, email, password_hash, is_active, created_at, updated_at
         FROM users
         WHERE id = ? AND is_active = 1
         LIMIT 1`
      )
      .bind(id)
      .first<UserRecord>();

    return row ?? null;
  }

  static async createUser(
    db: D1Database,
    params: { id: string; alias: string; email: string; passwordHash: string }
  ): Promise<{ id: string; alias: string; email: string; created_at: string }> {
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const normalizedEmail = params.email.trim().toLowerCase();

    await db
      .prepare(
        `INSERT INTO users (id, alias, email, password_hash, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`
      )
      .bind(params.id, params.alias.trim(), normalizedEmail, params.passwordHash, nowIso, nowIso)
      .run();

    return {
      id: params.id,
      alias: params.alias.trim(),
      email: normalizedEmail,
      created_at: nowIso
    };
  }

  static async saveRefreshToken(
    db: D1Database,
    params: {
      id: string;
      userId: string;
      tokenHash: string;
      userAgent: string | null;
      expiresAt: string;
    }
  ): Promise<void> {
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    await db
      .prepare(
        `INSERT INTO refresh_tokens (id, user_id, token_hash, user_agent, expires_at, revoked_at, created_at)
         VALUES (?, ?, ?, ?, ?, NULL, ?)`
      )
      .bind(
        params.id,
        params.userId,
        params.tokenHash,
        params.userAgent ? params.userAgent.slice(0, 255) : null,
        params.expiresAt,
        nowIso
      )
      .run();
  }

  static async findValidRefreshToken(
    db: D1Database,
    tokenHash: string
  ): Promise<RefreshTokenRecord | null> {
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const row = await db
      .prepare(
        `SELECT id, user_id, token_hash, user_agent, expires_at, revoked_at, created_at
         FROM refresh_tokens
         WHERE token_hash = ?
           AND revoked_at IS NULL
           AND expires_at > ?
         LIMIT 1`
      )
      .bind(tokenHash, nowIso)
      .first<RefreshTokenRecord>();

    return row ?? null;
  }

  static async rotateRefreshToken(
    db: D1Database,
    oldTokenId: string,
    nextToken: {
      id: string;
      userId: string;
      tokenHash: string;
      userAgent: string | null;
      expiresAt: string;
    }
  ): Promise<void> {
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

    await db.batch([
      db
        .prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?`)
        .bind(nowIso, oldTokenId),
      db
        .prepare(
          `INSERT INTO refresh_tokens (id, user_id, token_hash, user_agent, expires_at, revoked_at, created_at)
           VALUES (?, ?, ?, ?, ?, NULL, ?)`
        )
        .bind(
          nextToken.id,
          nextToken.userId,
          nextToken.tokenHash,
          nextToken.userAgent ? nextToken.userAgent.slice(0, 255) : null,
          nextToken.expiresAt,
          nowIso
        )
    ]);
  }

  static async revokeRefreshTokenByHash(db: D1Database, tokenHash: string): Promise<void> {
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    await db
      .prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`)
      .bind(nowIso, tokenHash)
      .run();
  }
}
