import type { D1Database } from '../types.ts';

const BASELINE_TOTAL_SCANS = 142_890;
const BASELINE_CRITICAL_BLOCKED = 18_430;

export function maskDomain(domain: string): string {
  return domain.replace(/\./g, '[.]');
}

export class CommercialRepository {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  async getLandingFeedData(): Promise<{
    metrics: {
      total_scans_executed: number;
      critical_threats_blocked: number;
      avg_scan_duration_ms: number;
    };
    recent_alerts: Array<{
      alert_id: string;
      scan_id: string;
      masked_domain: string;
      risk_score: number;
      threat_category: string;
      channel_received: string;
      detected_at: string;
    }>;
  }> {
    const metricsRow = await this.db
      .prepare(
        `SELECT
          COUNT(*) AS db_scans,
          SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS db_critical,
          AVG(scan_duration_ms) AS avg_ms
         FROM scans`
      )
      .first<{ db_scans: number; db_critical: number | null; avg_ms: number | null }>();

    const alertsRes = await this.db
      .prepare(
        `SELECT id, scan_id, target_domain, risk_score, threat_category_label, channel_received, created_at
         FROM community_alerts
         WHERE status = 'published'
         ORDER BY created_at DESC
         LIMIT 6`
      )
      .all<{
        id: string;
        scan_id: string;
        target_domain: string;
        risk_score: number;
        threat_category_label: string;
        channel_received: string;
        created_at: string;
      }>();

    const dbScans = Number(metricsRow?.db_scans ?? 0);
    const dbCritical = Number(metricsRow?.db_critical ?? 0);
    const avgMs = Math.round(Number(metricsRow?.avg_ms ?? 1380)) || 1380;

    return {
      metrics: {
        total_scans_executed: BASELINE_TOTAL_SCANS + dbScans,
        critical_threats_blocked: BASELINE_CRITICAL_BLOCKED + dbCritical,
        avg_scan_duration_ms: avgMs,
      },
      recent_alerts: (alertsRes.results ?? []).map((row) => ({
        alert_id: row.id,
        scan_id: row.scan_id,
        masked_domain: maskDomain(row.target_domain),
        risk_score: row.risk_score,
        threat_category: row.threat_category_label,
        channel_received: row.channel_received,
        detected_at: row.created_at,
      })),
    };
  }

  async createLead(params: {
    id: string;
    userId: string | null;
    planSelected: 'family_shield' | 'verified_merchant';
    fullName: string;
    email: string;
    phoneOrDomain: string;
    notes: string | null;
  }): Promise<{
    lead_id: string;
    plan_selected: 'family_shield' | 'verified_merchant';
    status: string;
    created_at: string;
  }> {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    await this.db
      .prepare(
        `INSERT INTO commercial_leads (
          id, user_id, plan_selected, full_name, email, phone_or_domain, notes, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_activation', ?)`
      )
      .bind(
        params.id,
        params.userId,
        params.planSelected,
        params.fullName.trim(),
        params.email.toLowerCase().trim(),
        params.phoneOrDomain.trim(),
        params.notes ? params.notes.trim().slice(0, 500) : null,
        now
      )
      .run();

    return {
      lead_id: params.id,
      plan_selected: params.planSelected,
      status: 'pending_activation',
      created_at: now,
    };
  }

  async createCommunityAlert(params: {
    id: string;
    scanId: string;
    userId: string;
    targetDomain: string;
    riskScore: number;
    threatCategoryLabel: string;
    channelReceived: string;
  }): Promise<{
    alert_id: string;
    masked_domain: string;
    created_at: string;
  }> {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const validChannels = new Set(['whatsapp', 'telegram', 'sms', 'email', 'social', 'web']);
    const channel = validChannels.has(params.channelReceived)
      ? params.channelReceived
      : 'whatsapp';

    await this.db
      .prepare(
        `INSERT INTO community_alerts (
          id, scan_id, reported_by_user_id, target_domain, risk_score,
          threat_category_label, channel_received, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'published', ?)`
      )
      .bind(
        params.id,
        params.scanId,
        params.userId,
        params.targetDomain,
        params.riskScore,
        params.threatCategoryLabel.slice(0, 120),
        channel,
        now
      )
      .run();

    return {
      alert_id: params.id,
      masked_domain: maskDomain(params.targetDomain),
      created_at: now,
    };
  }
}
