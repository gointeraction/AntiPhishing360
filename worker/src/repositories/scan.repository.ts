import type {
  D1Database,
  LinkFunctionalityAuditDTO,
  PhishingForensicsDossierDTO,
  RiskLevel,
  ScanFindingDTO,
  ScanReportDTO,
  SourcePreviewLine,
  VisualBrandAuditDTO,
} from '../types.ts';

interface ScanRow {
  id: string;
  user_id: string | null;
  target_url: string;
  final_url: string;
  target_domain: string;
  protocol: 'http' | 'https';
  http_status_code: number;
  redirect_count: number;
  has_hsts: number;
  has_csp: number;
  has_x_frame_options: number;
  risk_score: number;
  risk_level: RiskLevel;
  citizen_verdict_title: string;
  citizen_verdict_summary: string;
  action_steps_json: string;
  source_preview_json: string;
  r2_snapshot_key: string | null;
  integrity_sha256: string;
  scan_duration_ms: number;
  created_at: string;
}

export class ScanRepository {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  async createScanWithFindings(params: {
    report: ScanReportDTO;
    userId: string | null;
    finalUrl: string;
    httpStatusCode: number;
    r2SnapshotKey: string | null;
  }): Promise<void> {
    const r = params.report;
    const statements = [
      this.db
        .prepare(
          `INSERT INTO scans (
            id, user_id, target_url, final_url, target_domain, protocol, http_status_code,
            redirect_count, has_hsts, has_csp, has_x_frame_options, risk_score, risk_level,
            citizen_verdict_title, citizen_verdict_summary, action_steps_json, source_preview_json,
            r2_snapshot_key, integrity_sha256, scan_duration_ms, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          r.scan_id,
          params.userId,
          r.target_url,
          params.finalUrl,
          r.target_domain,
          r.transport_audit.protocol,
          params.httpStatusCode,
          r.transport_audit.redirect_count,
          r.transport_audit.security_headers.strict_transport_security ? 1 : 0,
          r.transport_audit.security_headers.content_security_policy ? 1 : 0,
          r.transport_audit.security_headers.x_frame_options ? 1 : 0,
          r.risk_score,
          r.risk_level,
          r.citizen_verdict.title,
          r.citizen_verdict.summary,
          JSON.stringify(r.citizen_verdict.action_steps),
          JSON.stringify(r.source_preview),
          params.r2SnapshotKey,
          r.integrity_sha256,
          r.duration_ms,
          r.scanned_at
        ),
    ];

    for (const f of r.findings) {
      statements.push(
        this.db
          .prepare(
            `INSERT INTO scan_findings (
              id, scan_id, rule_code, category, severity, line_number, column_number,
              dom_selector, citizen_explanation, technical_detail, code_snippet, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            f.id,
            r.scan_id,
            f.rule_code,
            f.category,
            f.severity,
            f.line_number,
            f.column_number,
            f.dom_selector,
            f.citizen_explanation,
            f.technical_detail,
            f.code_snippet,
            r.scanned_at
          )
      );
    }

    if (r.link_functionality || r.visual_brand_audit) {
      statements.push(
        this.db
          .prepare(
            `INSERT OR REPLACE INTO scan_deep_audits (
              scan_id, link_functionality_json, visual_brand_audit_json, created_at
            ) VALUES (?, ?, ?, ?)`
          )
          .bind(
            r.scan_id,
            JSON.stringify(r.link_functionality || null),
            JSON.stringify(r.visual_brand_audit || null),
            r.scanned_at
          )
      );
    }

    if (r.phishing_forensics) {
      statements.push(
        this.db
          .prepare(
            `INSERT OR REPLACE INTO scan_forensic_dossiers (
              scan_id, phishing_forensics_json, created_at
            ) VALUES (?, ?, ?)`
          )
          .bind(r.scan_id, JSON.stringify(r.phishing_forensics), r.scanned_at)
      );
    }

    await this.db.batch(statements);
  }

  async findReportById(scanId: string): Promise<ScanReportDTO | null> {
    const row = await this.db
      .prepare('SELECT * FROM scans WHERE id = ? LIMIT 1')
      .bind(scanId)
      .first<ScanRow>();

    if (!row) return null;

    const deepRow = await this.db
      .prepare(
        'SELECT link_functionality_json, visual_brand_audit_json FROM scan_deep_audits WHERE scan_id = ? LIMIT 1'
      )
      .bind(scanId)
      .first<{ link_functionality_json: string; visual_brand_audit_json: string }>();

    const dossierRow = await this.db
      .prepare(
        'SELECT phishing_forensics_json FROM scan_forensic_dossiers WHERE scan_id = ? LIMIT 1'
      )
      .bind(scanId)
      .first<{ phishing_forensics_json: string }>();

    const findingsResult = await this.db
      .prepare(
        `SELECT id, rule_code, category, severity, line_number, column_number,
                dom_selector, citizen_explanation, technical_detail, code_snippet
         FROM scan_findings
         WHERE scan_id = ?
         ORDER BY CASE severity
           WHEN 'CRITICAL' THEN 1
           WHEN 'HIGH' THEN 2
           WHEN 'MEDIUM' THEN 3
           ELSE 4
         END, line_number ASC`
      )
      .bind(scanId)
      .all<ScanFindingDTO>();

    let actionSteps: string[] = [];
    let sourcePreview: SourcePreviewLine[] = [];
    try {
      actionSteps = JSON.parse(row.action_steps_json);
    } catch {
      actionSteps = [];
    }
    try {
      sourcePreview = JSON.parse(row.source_preview_json);
    } catch {
      sourcePreview = [];
    }

    let linkFunctionality: LinkFunctionalityAuditDTO | undefined;
    let visualBrandAudit: VisualBrandAuditDTO | undefined;
    if (deepRow) {
      try {
        linkFunctionality = JSON.parse(deepRow.link_functionality_json) || undefined;
      } catch {
        linkFunctionality = undefined;
      }
      try {
        visualBrandAudit = JSON.parse(deepRow.visual_brand_audit_json) || undefined;
      } catch {
        visualBrandAudit = undefined;
      }
    }

    let phishingForensics: PhishingForensicsDossierDTO | undefined;
    if (dossierRow) {
      try {
        phishingForensics = JSON.parse(dossierRow.phishing_forensics_json) || undefined;
      } catch {
        phishingForensics = undefined;
      }
    }

    return {
      scan_id: row.id,
      target_url: row.target_url,
      final_url: row.final_url,
      target_domain: row.target_domain,
      scanned_at: row.created_at,
      duration_ms: row.scan_duration_ms,
      risk_score: row.risk_score,
      risk_level: row.risk_level,
      citizen_verdict: {
        title: row.citizen_verdict_title,
        summary: row.citizen_verdict_summary,
        action_steps: actionSteps,
      },
      transport_audit: {
        protocol: row.protocol,
        is_https: row.protocol === 'https',
        http_status_code: row.http_status_code,
        redirect_count: row.redirect_count,
        security_headers: {
          strict_transport_security: row.has_hsts === 1,
          content_security_policy: row.has_csp === 1,
          x_frame_options: row.has_x_frame_options === 1,
        },
      },
      link_functionality: linkFunctionality,
      visual_brand_audit: visualBrandAudit,
      phishing_forensics: phishingForensics,
      findings: findingsResult.results ?? [],
      source_preview: sourcePreview,
      integrity_sha256: row.integrity_sha256,
    };
  }

  async findUserHistory(params: {
    userId: string;
    page: number;
    limit: number;
    riskLevel?: string;
  }): Promise<{
    items: Array<{
      scan_id: string;
      target_url: string;
      target_domain: string;
      risk_score: number;
      risk_level: RiskLevel;
      citizen_verdict_title: string;
      scanned_at: string;
    }>;
    total: number;
    stats: {
      total_analyzed: number;
      threats_avoided: number;
    };
  }> {
    const offset = (params.page - 1) * params.limit;
    const validLevel =
      params.riskLevel && ['SAFE', 'WARNING', 'CRITICAL'].includes(params.riskLevel)
        ? params.riskLevel
        : null;

    const statsRow = await this.db
      .prepare(
        `SELECT
          COUNT(*) AS total_analyzed,
          SUM(CASE WHEN risk_level IN ('WARNING', 'CRITICAL') THEN 1 ELSE 0 END) AS threats_avoided
         FROM scans WHERE user_id = ?`
      )
      .bind(params.userId)
      .first<{ total_analyzed: number; threats_avoided: number | null }>();

    let total = 0;
    let items: Array<{
      scan_id: string;
      target_url: string;
      target_domain: string;
      risk_score: number;
      risk_level: RiskLevel;
      citizen_verdict_title: string;
      scanned_at: string;
    }> = [];

    if (validLevel) {
      const countRow = await this.db
        .prepare('SELECT COUNT(*) AS total FROM scans WHERE user_id = ? AND risk_level = ?')
        .bind(params.userId, validLevel)
        .first<{ total: number }>();
      total = Number(countRow?.total ?? 0);

      const listRes = await this.db
        .prepare(
          `SELECT id AS scan_id, target_url, target_domain, risk_score, risk_level,
                  citizen_verdict_title, created_at AS scanned_at
           FROM scans
           WHERE user_id = ? AND risk_level = ?
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?`
        )
        .bind(params.userId, validLevel, params.limit, offset)
        .all<{
          scan_id: string;
          target_url: string;
          target_domain: string;
          risk_score: number;
          risk_level: RiskLevel;
          citizen_verdict_title: string;
          scanned_at: string;
        }>();
      items = listRes.results ?? [];
    } else {
      total = Number(statsRow?.total_analyzed ?? 0);
      const listRes = await this.db
        .prepare(
          `SELECT id AS scan_id, target_url, target_domain, risk_score, risk_level,
                  citizen_verdict_title, created_at AS scanned_at
           FROM scans
           WHERE user_id = ?
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?`
        )
        .bind(params.userId, params.limit, offset)
        .all<{
          scan_id: string;
          target_url: string;
          target_domain: string;
          risk_score: number;
          risk_level: RiskLevel;
          citizen_verdict_title: string;
          scanned_at: string;
        }>();
      items = listRes.results ?? [];
    }

    return {
      items,
      total,
      stats: {
        total_analyzed: Number(statsRow?.total_analyzed ?? 0),
        threats_avoided: Number(statsRow?.threats_avoided ?? 0),
      },
    };
  }

  async saveClarityVote(id: string, scanId: string, isClear: boolean): Promise<void> {
    await this.db
      .prepare('INSERT INTO clarity_feedback (id, scan_id, is_clear) VALUES (?, ?, ?)')
      .bind(id, scanId, isClear ? 1 : 0)
      .run();
  }
}
