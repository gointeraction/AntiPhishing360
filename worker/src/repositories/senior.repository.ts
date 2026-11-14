import type { D1Database, RiskLevel } from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';

export interface GuardianConsultationRow {
  id: string;
  token: string;
  scan_id: string | null;
  senior_name: string;
  guardian_name: string;
  guardian_phone: string;
  alert_mode: 'ASK_GUARDIAN' | 'AUTO_CRITICAL_ALERT';
  target_url: string;
  message_excerpt: string;
  risk_score: number;
  risk_level: RiskLevel;
  guardian_decision: 'PENDING' | 'SAFE_APPROVED' | 'DANGER_DELETE';
  guardian_note: string;
  responded_at: string | null;
  created_at: string;
}

export interface VerifiedDirectoryEntry {
  id: string;
  slug: string;
  entity_name: string;
  category: 'BANCO' | 'ORGANISMO_PUBLICO' | 'ENVIOS' | 'EMERGENCIA';
  official_domain: string;
  official_url: string;
  emergency_phone: string;
  customer_phone: string;
  never_asks_notice: string;
  search_keywords: string;
}

export type GuardianEventType =
  | 'URL_SCAN'
  | 'MESSAGE_SCAN'
  | 'QR_SCAN'
  | 'ASK_GUARDIAN'
  | 'AUTO_CRITICAL_ALERT'
  | 'EMERGENCY_TRIGGERED';

export type GuardianFamilyStatus =
  | 'INFO'
  | 'PENDING'
  | 'SAFE_APPROVED'
  | 'DANGER_DELETE'
  | 'RESOLVED_BY_CALL';

export interface GuardianFamilyLinkRow {
  id: string;
  family_code: string;
  senior_name: string;
  senior_phone: string;
  guardian_name: string;
  guardian_phone: string;
  pin_hash: string;
  latest_family_broadcast: string;
  broadcast_updated_at: string | null;
  last_senior_activity_at: string;
  created_at: string;
}

export interface GuardianActivityEventRow {
  id: string;
  family_code: string;
  consultation_token: string | null;
  scan_id: string | null;
  event_type: GuardianEventType;
  target_url: string;
  content_summary: string;
  risk_score: number;
  risk_level: RiskLevel;
  family_status: GuardianFamilyStatus;
  family_note: string;
  responded_at: string | null;
  created_at: string;
}

export class SeniorRepository {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  private generateShortToken(): string {
    const alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    const bytes = new Uint8Array(10);
    crypto.getRandomValues(bytes);
    let out = 'GRD';
    for (let i = 0; i < bytes.length; i++) {
      out += alphabet[bytes[i] % alphabet.length];
    }
    return out;
  }

  async createGuardianConsultation(params: {
    scanId?: string | null;
    seniorName: string;
    guardianName: string;
    guardianPhone: string;
    alertMode: 'ASK_GUARDIAN' | 'AUTO_CRITICAL_ALERT';
    targetUrl: string;
    messageExcerpt: string;
    riskScore: number;
    riskLevel: RiskLevel;
  }): Promise<GuardianConsultationRow> {
    const id = CryptoService.generateUlid('grd');
    const token = this.generateShortToken();
    const createdAt = new Date().toISOString();

    let verifiedScanId: string | null = null;
    if (params.scanId) {
      const scanExists = await this.db
        .prepare(`SELECT id FROM scans WHERE id = ? LIMIT 1`)
        .bind(params.scanId)
        .first<{ id: string }>();
      if (scanExists) verifiedScanId = scanExists.id;
    }

    await this.db
      .prepare(
        `INSERT INTO guardian_consultations (
          id, token, scan_id, senior_name, guardian_name, guardian_phone,
          alert_mode, target_url, message_excerpt, risk_score, risk_level,
          guardian_decision, guardian_note, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', '', ?)`
      )
      .bind(
        id,
        token,
        verifiedScanId,
        params.seniorName.slice(0, 80) || 'Familiar Mayor',
        params.guardianName.slice(0, 80) || 'Familiar de Confianza',
        params.guardianPhone.slice(0, 40),
        params.alertMode,
        params.targetUrl.slice(0, 500),
        params.messageExcerpt.slice(0, 600),
        Math.max(0, Math.min(100, Math.round(params.riskScore))),
        params.riskLevel,
        createdAt
      )
      .run();

    const row = await this.getConsultationByToken(token);
    if (!row) {
      throw new Error('No se pudo recuperar la consulta de Ángel Guardián.');
    }
    return row;
  }

  async getConsultationByToken(token: string): Promise<GuardianConsultationRow | null> {
    return await this.db
      .prepare(`SELECT * FROM guardian_consultations WHERE token = ? LIMIT 1`)
      .bind(token.trim().toUpperCase())
      .first<GuardianConsultationRow>();
  }

  async replyToConsultation(params: {
    token: string;
    decision: 'SAFE_APPROVED' | 'DANGER_DELETE';
    note: string;
  }): Promise<GuardianConsultationRow | null> {
    const cleanToken = params.token.trim().toUpperCase();
    const nowIso = new Date().toISOString();
    const res = await this.db
      .prepare(
        `UPDATE guardian_consultations
         SET guardian_decision = ?,
             guardian_note = ?,
             responded_at = ?
         WHERE token = ?`
      )
      .bind(params.decision, params.note.slice(0, 400), nowIso, cleanToken)
      .run();

    if (!res.meta || Number(res.meta.changes) === 0) {
      return null;
    }
    return await this.getConsultationByToken(cleanToken);
  }

  async searchVerifiedDirectory(params: {
    query?: string;
    category?: string;
  }): Promise<VerifiedDirectoryEntry[]> {
    const q = (params.query || '')
      .trim()
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '');
    const cat = (params.category || 'ALL').trim().toUpperCase();

    const validCategories = new Set(['BANCO', 'ORGANISMO_PUBLICO', 'ENVIOS', 'EMERGENCIA']);
    let rows: VerifiedDirectoryEntry[];

    if (validCategories.has(cat)) {
      const r = await this.db
        .prepare(`SELECT * FROM verified_directory WHERE category = ? ORDER BY entity_name ASC`)
        .bind(cat)
        .all<VerifiedDirectoryEntry>();
      rows = r.results;
    } else {
      const r = await this.db
        .prepare(`SELECT * FROM verified_directory ORDER BY category ASC, entity_name ASC`)
        .all<VerifiedDirectoryEntry>();
      rows = r.results;
    }

    if (!q) return rows;

    return rows.filter((entry) => {
      const hay = `${entry.entity_name} ${entry.official_domain} ${entry.search_keywords} ${entry.slug}`
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '');
      return hay.includes(q);
    });
  }

  async getDirectoryEntryBySlug(slug: string): Promise<VerifiedDirectoryEntry | null> {
    return await this.db
      .prepare(`SELECT * FROM verified_directory WHERE slug = ? LIMIT 1`)
      .bind(slug.trim().toLowerCase())
      .first<VerifiedDirectoryEntry>();
  }

  // --------------------------------------------------------------------------
  // PORTAL DEL FAMILIAR: VÍNCULO SEGURO Y BITÁCORA EN TIEMPO REAL
  // --------------------------------------------------------------------------
  private generateFamilyCode(): string {
    const alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    let suffix = '';
    for (let i = 0; i < bytes.length; i++) {
      suffix += alphabet[bytes[i] % alphabet.length];
    }
    return `FAM-360-${suffix}`;
  }

  async createFamilyLink(params: {
    seniorName: string;
    seniorPhone: string;
    guardianName: string;
    guardianPhone: string;
    pinHash: string;
  }): Promise<GuardianFamilyLinkRow> {
    const id = CryptoService.generateUlid('flk');
    const familyCode = this.generateFamilyCode();
    const nowIso = new Date().toISOString();

    await this.db
      .prepare(
        `INSERT INTO guardian_family_links (
          id, family_code, senior_name, senior_phone, guardian_name, guardian_phone,
          pin_hash, latest_family_broadcast, last_senior_activity_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?)`
      )
      .bind(
        id,
        familyCode,
        params.seniorName.slice(0, 80) || 'Abuelo / Familiar Mayor',
        params.seniorPhone.slice(0, 40),
        params.guardianName.slice(0, 80) || 'Familiar Guardián',
        params.guardianPhone.slice(0, 40),
        params.pinHash,
        nowIso,
        nowIso
      )
      .run();

    const row = await this.getFamilyLinkByCode(familyCode);
    if (!row) {
      throw new Error('No se pudo crear el vínculo familiar.');
    }
    return row;
  }

  async getFamilyLinkByCode(familyCode: string): Promise<GuardianFamilyLinkRow | null> {
    return await this.db
      .prepare(`SELECT * FROM guardian_family_links WHERE family_code = ? LIMIT 1`)
      .bind(familyCode.trim().toUpperCase())
      .first<GuardianFamilyLinkRow>();
  }

  async recordFamilyActivityEvent(params: {
    familyCode: string;
    consultationToken?: string | null;
    scanId?: string | null;
    eventType: GuardianEventType;
    targetUrl: string;
    contentSummary: string;
    riskScore: number;
    riskLevel: RiskLevel;
    familyStatus?: GuardianFamilyStatus;
  }): Promise<GuardianActivityEventRow | null> {
    const code = params.familyCode.trim().toUpperCase();
    const link = await this.getFamilyLinkByCode(code);
    if (!link) return null;

    let validScanId: string | null = null;
    if (params.scanId) {
      const scanExists = await this.db
        .prepare(`SELECT id FROM scans WHERE id = ? LIMIT 1`)
        .bind(params.scanId)
        .first<{ id: string }>();
      if (scanExists) validScanId = scanExists.id;
    }

    const id = CryptoService.generateUlid('gaf');
    const nowIso = new Date().toISOString();
    const defaultStatus: GuardianFamilyStatus =
      params.familyStatus ||
      (params.eventType === 'ASK_GUARDIAN' ||
      params.eventType === 'AUTO_CRITICAL_ALERT' ||
      params.eventType === 'EMERGENCY_TRIGGERED' ||
      params.riskLevel === 'CRITICAL'
        ? 'PENDING'
        : 'INFO');

    await this.db
      .prepare(
        `INSERT INTO guardian_activity_feed (
          id, family_code, consultation_token, scan_id, event_type, target_url,
          content_summary, risk_score, risk_level, family_status, family_note, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?)`
      )
      .bind(
        id,
        code,
        params.consultationToken || null,
        validScanId,
        params.eventType,
        params.targetUrl.slice(0, 500),
        params.contentSummary.slice(0, 600),
        Math.max(0, Math.min(100, Math.round(params.riskScore))),
        params.riskLevel,
        defaultStatus,
        nowIso
      )
      .run();

    await this.db
      .prepare(`UPDATE guardian_family_links SET last_senior_activity_at = ? WHERE family_code = ?`)
      .bind(nowIso, code)
      .run();

    return await this.db
      .prepare(`SELECT * FROM guardian_activity_feed WHERE id = ? LIMIT 1`)
      .bind(id)
      .first<GuardianActivityEventRow>();
  }

  async listFamilyActivityFeed(params: {
    familyCode: string;
    filter?: string;
    limit?: number;
  }): Promise<GuardianActivityEventRow[]> {
    const code = params.familyCode.trim().toUpperCase();
    const filter = (params.filter || 'ALL').toUpperCase();
    const limit = Math.min(120, Math.max(10, params.limit || 60));

    if (filter === 'PENDING') {
      const r = await this.db
        .prepare(
          `SELECT * FROM guardian_activity_feed
           WHERE family_code = ? AND family_status = 'PENDING'
           ORDER BY created_at DESC LIMIT ?`
        )
        .bind(code, limit)
        .all<GuardianActivityEventRow>();
      return r.results;
    }

    if (filter === 'CRITICAL') {
      const r = await this.db
        .prepare(
          `SELECT * FROM guardian_activity_feed
           WHERE family_code = ? AND risk_level = 'CRITICAL'
           ORDER BY created_at DESC LIMIT ?`
        )
        .bind(code, limit)
        .all<GuardianActivityEventRow>();
      return r.results;
    }

    if (filter === 'EMERGENCY') {
      const r = await this.db
        .prepare(
          `SELECT * FROM guardian_activity_feed
           WHERE family_code = ? AND event_type = 'EMERGENCY_TRIGGERED'
           ORDER BY created_at DESC LIMIT ?`
        )
        .bind(code, limit)
        .all<GuardianActivityEventRow>();
      return r.results;
    }

    const r = await this.db
      .prepare(
        `SELECT * FROM guardian_activity_feed
         WHERE family_code = ?
         ORDER BY created_at DESC LIMIT ?`
      )
      .bind(code, limit)
      .all<GuardianActivityEventRow>();
    return r.results;
  }

  async updateFamilyEventDecision(params: {
    familyCode: string;
    eventId: string;
    status: 'SAFE_APPROVED' | 'DANGER_DELETE' | 'RESOLVED_BY_CALL';
    note: string;
  }): Promise<GuardianActivityEventRow | null> {
    const code = params.familyCode.trim().toUpperCase();
    const nowIso = new Date().toISOString();

    const existing = await this.db
      .prepare(
        `SELECT * FROM guardian_activity_feed WHERE id = ? AND family_code = ? LIMIT 1`
      )
      .bind(params.eventId, code)
      .first<GuardianActivityEventRow>();
    if (!existing) return null;

    await this.db
      .prepare(
        `UPDATE guardian_activity_feed
         SET family_status = ?, family_note = ?, responded_at = ?
         WHERE id = ? AND family_code = ?`
      )
      .bind(params.status, params.note.slice(0, 400), nowIso, params.eventId, code)
      .run();

    // Si el evento estaba asociado a una consulta en 1 toque, sincronizar también guardian_consultations
    if (
      existing.consultation_token &&
      (params.status === 'SAFE_APPROVED' || params.status === 'DANGER_DELETE')
    ) {
      await this.replyToConsultation({
        token: existing.consultation_token,
        decision: params.status,
        note: params.note,
      });
    }

    return await this.db
      .prepare(`SELECT * FROM guardian_activity_feed WHERE id = ? LIMIT 1`)
      .bind(params.eventId)
      .first<GuardianActivityEventRow>();
  }

  async updateFamilyBroadcast(params: {
    familyCode: string;
    message: string;
  }): Promise<GuardianFamilyLinkRow | null> {
    const code = params.familyCode.trim().toUpperCase();
    const nowIso = new Date().toISOString();
    const res = await this.db
      .prepare(
        `UPDATE guardian_family_links
         SET latest_family_broadcast = ?, broadcast_updated_at = ?
         WHERE family_code = ?`
      )
      .bind(params.message.slice(0, 360), nowIso, code)
      .run();

    if (!res.meta || Number(res.meta.changes) === 0) return null;
    return await this.getFamilyLinkByCode(code);
  }
}
