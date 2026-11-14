import type {
  CicpcCaseStatus,
  CicpcIncidentImpact,
  CicpcOfficerRole,
  CicpcPriority,
  CicpcStrategicAction,
  D1Database,
  RiskLevel,
} from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { ScanRepository } from './scan.repository.ts';

export interface OfficerRow {
  id: string;
  badge_id: string;
  full_name: string;
  rank_title: string;
  password_hash: string;
  security_key_sha256: string;
  role: CicpcOfficerRole;
  is_active: number;
}

export class CicpcRepository {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  async findOfficerByBadge(badgeId: string): Promise<OfficerRow | null> {
    return await this.db
      .prepare(
        `SELECT id, badge_id, full_name, rank_title, password_hash, security_key_sha256, role, is_active
         FROM cicpc_officers
         WHERE UPPER(badge_id) = UPPER(?)
         LIMIT 1`
      )
      .bind(badgeId.trim())
      .first<OfficerRow>();
  }

  async touchOfficerLogin(officerId: string): Promise<void> {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    await this.db
      .prepare(`UPDATE cicpc_officers SET last_login_at = ? WHERE id = ?`)
      .bind(now, officerId)
      .run();
  }

  async appendAuditLog(params: {
    officerBadge: string;
    officerName: string;
    actionCode: string;
    caseId?: string | null;
    detail: string;
    clientIp: string;
  }): Promise<void> {
    const id = CryptoService.generateUlid('aud');
    await this.db
      .prepare(
        `INSERT INTO cicpc_audit_logs (
          id, officer_badge, officer_name, action_code, case_id, detail, client_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        id,
        params.officerBadge,
        params.officerName,
        params.actionCode,
        params.caseId || null,
        params.detail.slice(0, 500),
        params.clientIp
      )
      .run();
  }

  async listAuditLogs(limit = 25): Promise<Record<string, unknown>[]> {
    const res = await this.db
      .prepare(
        `SELECT id, officer_badge, officer_name, action_code, case_id, detail, client_ip, created_at
         FROM cicpc_audit_logs
         ORDER BY created_at DESC
         LIMIT ?`
      )
      .bind(limit)
      .all<Record<string, unknown>>();
    return res.results;
  }

  private async generateNextCaseNumber(): Promise<string> {
    const countRow = await this.db
      .prepare(`SELECT COUNT(*) AS total FROM cicpc_cases`)
      .first<{ total: number }>();
    const nextSeq = 101 + Number(countRow?.total || 0);
    const randSuffix = Math.floor(10 + Math.random() * 89);
    return `EXP-DIDI-2026-${String(nextSeq).padStart(4, '0')}-${randSuffix}`;
  }

  async registerNotificationOrComplaint(params: {
    scanId: string;
    reportedByUserId: string | null;
    sourceType: 'CITIZEN_COMPLAINT' | 'COMMUNITY_ALERT' | 'AUTO_CRITICAL_DETECTION';
    targetUrl: string;
    targetDomain: string;
    riskScore: number;
    riskLevel: RiskLevel;
    channelReceived: string;
    impersonatedEntity?: string;
    suspectContact?: string;
    incidentImpact?: CicpcIncidentImpact;
    citizenStatement?: string;
    reporterContact?: string;
  }): Promise<{ id: string; case_number: string; status: string; priority: string }> {
    const validChannels = new Set(['whatsapp', 'telegram', 'sms', 'email', 'social', 'web']);
    const channel = validChannels.has(params.channelReceived) ? params.channelReceived : 'whatsapp';
    const impact: CicpcIncidentImpact =
      params.incidentImpact === 'FINANCIAL_LOSS' || params.incidentImpact === 'CREDENTIALS_EXPOSED'
        ? params.incidentImpact
        : 'PREVENTIVE';

    const priority: CicpcPriority =
      impact === 'FINANCIAL_LOSS' || impact === 'CREDENTIALS_EXPOSED' || params.riskScore >= 95
        ? 'URGENT'
        : params.riskScore >= 70
        ? 'HIGH'
        : 'NORMAL';

    const existingForScan = await this.db
      .prepare(
        `SELECT id, case_number, source_type, citizen_statement, status, priority
         FROM cicpc_cases
         WHERE scan_id = ?
         ORDER BY created_at ASC
         LIMIT 1`
      )
      .bind(params.scanId)
      .first<{
        id: string;
        case_number: string;
        source_type: string;
        citizen_statement: string;
        status: string;
        priority: string;
      }>();

    // Avoid duplicate background auto-detections on the exact same scan
    if (existingForScan && params.sourceType !== 'CITIZEN_COMPLAINT') {
      return {
        id: existingForScan.id,
        case_number: existingForScan.case_number,
        status: existingForScan.status,
        priority: existingForScan.priority,
      };
    }

    // Upgrade an existing auto-detected record if the user now submits a formal citizen complaint for that scan
    if (
      existingForScan &&
      params.sourceType === 'CITIZEN_COMPLAINT' &&
      existingForScan.source_type !== 'CITIZEN_COMPLAINT'
    ) {
      const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
      await this.db
        .prepare(
          `UPDATE cicpc_cases
           SET source_type = 'CITIZEN_COMPLAINT',
               reported_by_user_id = COALESCE(?, reported_by_user_id),
               channel_received = ?,
               impersonated_entity = ?,
               suspect_contact = ?,
               incident_impact = ?,
               citizen_statement = ?,
               reporter_contact = ?,
               priority = ?,
               updated_at = ?
           WHERE id = ?`
        )
        .bind(
          params.reportedByUserId,
          channel,
          (params.impersonatedEntity || 'No especificada').slice(0, 120),
          (params.suspectContact || '').slice(0, 120),
          impact,
          (params.citizenStatement || '').slice(0, 1200),
          (params.reporterContact || '').slice(0, 120),
          priority,
          now,
          existingForScan.id
        )
        .run();

      return {
        id: existingForScan.id,
        case_number: existingForScan.case_number,
        status: existingForScan.status,
        priority,
      };
    }

    const id = CryptoService.generateUlid('cas');
    const caseNumber = await this.generateNextCaseNumber();

    await this.db
      .prepare(
        `INSERT INTO cicpc_cases (
          id, case_number, scan_id, reported_by_user_id, source_type,
          target_url, target_domain, risk_score, risk_level, channel_received,
          impersonated_entity, suspect_contact, incident_impact, citizen_statement,
          reporter_contact, priority, status, strategic_action_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'NONE')`
      )
      .bind(
        id,
        caseNumber,
        params.scanId,
        params.reportedByUserId,
        params.sourceType,
        params.targetUrl,
        params.targetDomain,
        params.riskScore,
        params.riskLevel,
        channel,
        (params.impersonatedEntity || 'Por clasificar').slice(0, 120),
        (params.suspectContact || '').slice(0, 120),
        impact,
        (params.citizenStatement || '').slice(0, 1200),
        (params.reporterContact || '').slice(0, 120),
        priority
      )
      .run();

    return {
      id,
      case_number: caseNumber,
      status: 'pending',
      priority,
    };
  }

  async getStrategicDashboardStats(): Promise<Record<string, unknown>> {
    const totals = await this.db
      .prepare(
        `SELECT
           COUNT(*) AS total_cases,
           SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_cases,
           SUM(CASE WHEN status = 'in_analysis' THEN 1 ELSE 0 END) AS analysis_cases,
           SUM(CASE WHEN status IN ('strategic_action', 'mitigated') THEN 1 ELSE 0 END) AS actioned_cases,
           SUM(CASE WHEN priority = 'URGENT' THEN 1 ELSE 0 END) AS urgent_cases,
           SUM(CASE WHEN incident_impact IN ('CREDENTIALS_EXPOSED', 'FINANCIAL_LOSS') THEN 1 ELSE 0 END) AS affected_victims
         FROM cicpc_cases`
      )
      .first<Record<string, number>>();

    const activeCampaigns = await this.db
      .prepare(
        `SELECT
           target_domain,
           COUNT(*) AS reports_count,
           MAX(risk_score) AS max_risk_score,
           MAX(impersonated_entity) AS impersonated_entity,
           MAX(channel_received) AS primary_channel,
           MAX(strategic_action_type) AS strategic_action_type,
           MAX(status) AS latest_status,
           MAX(created_at) AS last_seen_at
         FROM cicpc_cases
         GROUP BY target_domain
         ORDER BY reports_count DESC, max_risk_score DESC
         LIMIT 8`
      )
      .all<Record<string, unknown>>();

    const byChannel = await this.db
      .prepare(
        `SELECT channel_received, COUNT(*) AS total
         FROM cicpc_cases
         GROUP BY channel_received
         ORDER BY total DESC`
      )
      .all<Record<string, unknown>>();

    return {
      kpis: {
        total_cases: Number(totals?.total_cases || 0),
        pending_cases: Number(totals?.pending_cases || 0),
        analysis_cases: Number(totals?.analysis_cases || 0),
        actioned_cases: Number(totals?.actioned_cases || 0),
        urgent_cases: Number(totals?.urgent_cases || 0),
        affected_victims: Number(totals?.affected_victims || 0),
      },
      campaigns: activeCampaigns.results,
      channels: byChannel.results,
    };
  }

  async listCases(filters: {
    status?: string;
    priority?: string;
    channel?: string;
    search?: string;
    limit?: number;
  }): Promise<Record<string, unknown>[]> {
    const clauses: string[] = ['1 = 1'];
    const params: unknown[] = [];

    if (filters.status && filters.status !== 'all') {
      clauses.push('c.status = ?');
      params.push(filters.status);
    }

    if (filters.priority && filters.priority !== 'all') {
      clauses.push('c.priority = ?');
      params.push(filters.priority);
    }

    if (filters.channel && filters.channel !== 'all') {
      clauses.push('c.channel_received = ?');
      params.push(filters.channel);
    }

    if (filters.search && filters.search.trim()) {
      const term = `%${filters.search.trim()}%`;
      clauses.push(
        '(c.case_number LIKE ? OR c.target_domain LIKE ? OR c.target_url LIKE ? OR c.impersonated_entity LIKE ? OR c.suspect_contact LIKE ?)'
      );
      params.push(term, term, term, term, term);
    }

    const limit = Math.min(100, Math.max(1, filters.limit || 50));
    params.push(limit);

    const res = await this.db
      .prepare(
        `SELECT
           c.id,
           c.case_number,
           c.scan_id,
           c.source_type,
           c.target_url,
           c.target_domain,
           c.risk_score,
           c.risk_level,
           c.channel_received,
           c.impersonated_entity,
           c.suspect_contact,
           c.incident_impact,
           c.citizen_statement,
           c.reporter_contact,
           c.priority,
           c.status,
           c.strategic_action_type,
           c.expert_notes,
           c.reviewed_by_badge,
           c.reviewed_by_name,
           c.reviewed_at,
           c.created_at,
           c.updated_at,
           u.alias AS reporter_alias
         FROM cicpc_cases c
         LEFT JOIN users u ON u.id = c.reported_by_user_id
         WHERE ${clauses.join(' AND ')}
         ORDER BY
           CASE c.priority WHEN 'URGENT' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END ASC,
           c.created_at DESC
         LIMIT ?`
      )
      .bind(...params)
      .all<Record<string, unknown>>();

    return res.results;
  }

  async getCaseDetailById(caseId: string): Promise<Record<string, unknown> | null> {
    const row = await this.db
      .prepare(
        `SELECT
           c.*,
           u.alias AS reporter_alias,
           u.email AS reporter_user_email
         FROM cicpc_cases c
         LEFT JOIN users u ON u.id = c.reported_by_user_id
         WHERE c.id = ? OR c.case_number = ?
         LIMIT 1`
      )
      .bind(caseId, caseId)
      .first<Record<string, unknown>>();

    if (!row) return null;

    const scanRepo = new ScanRepository(this.db);
    const forensicReport = await scanRepo.findReportById(String(row.scan_id));

    return {
      case_record: row,
      forensic_report: forensicReport,
    };
  }

  async updateCaseExpertReview(params: {
    caseId: string;
    status: CicpcCaseStatus;
    priority: CicpcPriority;
    strategicActionType: CicpcStrategicAction;
    expertNotes: string;
    officerBadge: string;
    officerName: string;
  }): Promise<boolean> {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const res = await this.db
      .prepare(
        `UPDATE cicpc_cases
         SET status = ?,
             priority = ?,
             strategic_action_type = ?,
             expert_notes = ?,
             reviewed_by_badge = ?,
             reviewed_by_name = ?,
             reviewed_at = ?,
             updated_at = ?
         WHERE id = ?`
      )
      .bind(
        params.status,
        params.priority,
        params.strategicActionType,
        params.expertNotes.slice(0, 2000),
        params.officerBadge,
        params.officerName,
        now,
        now,
        params.caseId
      )
      .run();

    return Number(res.meta?.changes ?? 0) > 0;
  }
}
