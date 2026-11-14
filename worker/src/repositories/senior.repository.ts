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
}
