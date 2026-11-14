import type { AuthUser, D1Database, PlanTier } from '../types.ts';

export interface UserRow {
  id: string;
  alias: string;
  email: string;
  password_hash: string;
  plan_tier: PlanTier;
  is_active: number;
  created_at: string;
  updated_at: string;
}

export class UserRepository {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  async findByEmail(email: string): Promise<UserRow | null> {
    return await this.db
      .prepare(
        'SELECT id, alias, email, password_hash, plan_tier, is_active, created_at, updated_at FROM users WHERE email = ? LIMIT 1'
      )
      .bind(email.toLowerCase().trim())
      .first<UserRow>();
  }

  async findById(id: string): Promise<AuthUser | null> {
    const row = await this.db
      .prepare(
        'SELECT id, alias, email, plan_tier, created_at FROM users WHERE id = ? AND is_active = 1 LIMIT 1'
      )
      .bind(id)
      .first<AuthUser>();
    return row ?? null;
  }

  async createUser(params: {
    id: string;
    alias: string;
    email: string;
    passwordHash: string;
    planTier?: PlanTier;
  }): Promise<AuthUser> {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const tier = params.planTier ?? 'citizen_free';
    const cleanEmail = params.email.toLowerCase().trim();

    await this.db
      .prepare(
        `INSERT INTO users (id, alias, email, password_hash, plan_tier, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 1, ?, ?)`
      )
      .bind(params.id, params.alias.trim(), cleanEmail, params.passwordHash, tier, now, now)
      .run();

    return {
      id: params.id,
      alias: params.alias.trim(),
      email: cleanEmail,
      plan_tier: tier,
      created_at: now,
    };
  }

  async claimAnonymousScan(scanId: string, userId: string): Promise<boolean> {
    const res = await this.db
      .prepare('UPDATE scans SET user_id = ? WHERE id = ? AND user_id IS NULL')
      .bind(userId, scanId)
      .run();
    return res.success;
  }

  async saveRefreshToken(params: {
    id: string;
    userId: string;
    tokenHash: string;
    userAgent: string;
    expiresAt: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO refresh_tokens (id, user_id, token_hash, user_agent, expires_at)
         VALUES (?, ?, ?, ?, ?)`
      )
      .bind(
        params.id,
        params.userId,
        params.tokenHash,
        params.userAgent.slice(0, 255),
        params.expiresAt
      )
      .run();
  }

  async revokeRefreshTokenByHash(tokenHash: string): Promise<void> {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    await this.db
      .prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
      .bind(now, tokenHash)
      .run();
  }

  async findValidRefreshToken(tokenHash: string): Promise<{ id: string; user_id: string } | null> {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    return await this.db
      .prepare(
        `SELECT id, user_id FROM refresh_tokens
         WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
         LIMIT 1`
      )
      .bind(tokenHash, now)
      .first<{ id: string; user_id: string }>();
  }
}
