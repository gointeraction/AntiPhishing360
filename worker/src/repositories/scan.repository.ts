import { ScoringService } from '../services/scoring.service';
import {
  AlertChannel,
  FindingCategory,
  FindingSeverity,
  RedirectHop,
  RiskLevel,
  ScanFinding,
  ScanReportData,
  SourcePreviewLine
} from '../types/models';
import { AppError } from '../utils/response';

interface ScanRow {
  id: string;
  user_id: string | null;
  target_url: string;
  final_url: string;
  target_domain: string;
  protocol: 'http' | 'https';
  http_status_code: number;
  redirect_count: number;
  redirect_chain_json: string;
  has_hsts: number;
  has_csp: number;
  has_x_frame_options: number;
  risk_score: number;
  risk_level: RiskLevel;
  citizen_verdict_title: string;
  citizen_verdict_summary: string;
  source_preview_json: string;
  r2_snapshot_key: string | null;
  case_note: string | null;
  integrity_sha256: string;
  scan_duration_ms: number;
  created_at: string;
}

interface FindingRow {
  id: string;
  scan_id: string;
  rule_code: string;
  category: FindingCategory;
  severity: FindingSeverity;
  line_number: number;
  column_number: number;
  dom_selector: string;
  citizen_explanation: string;
  technical_detail: string;
  code_snippet: string;
}

export class ScanRepository {
  static async getCachedScan(kv: KVNamespace | undefined, urlHash: string): Promise<ScanReportData | null> {
    if (!kv) return null;
    try {
      const raw = await kv.get(`scan_cache:${urlHash}`);
      if (!raw) return null;
      return JSON.parse(raw) as ScanReportData;
    } catch {
      return null;
    }
  }

  static async setCachedScan(
    kv: KVNamespace | undefined,
    urlHash: string,
    report: ScanReportData,
    ttlSeconds = 900
  ): Promise<void> {
    if (!kv) return;
    try {
      await kv.put(`scan_cache:${urlHash}`, JSON.stringify(report), {
        expirationTtl: ttlSeconds
      });
    } catch {
      // Non-fatal if KV write fails
    }
  }

  /**
   * Saves HTML source snapshot in R2 strictly as neutralized plain-text attachment
   * so it can never be rendered/executed as active HTML by a browser.
   */
  static async saveSanitizedSnapshot(
    r2: R2Bucket | undefined,
    scanId: string,
    targetUrl: string,
    rawHtml: string
  ): Promise<string | null> {
    if (!r2) return null;
    try {
      const datePrefix = new Date().toISOString().slice(0, 10);
      const objectKey = `snapshots/${datePrefix}/${scanId}.txt`;
      const sanitizedBanner = [
        `# DETECTOR360 FORENSIC EVIDENCE SNAPSHOT (PLAIN TEXT ESCAPED)`,
        `# Scan ID: ${scanId}`,
        `# Target URL: ${targetUrl}`,
        `# Captured At (UTC): ${new Date().toISOString()}`,
        `# WARNING: Untrusted external source code — DO NOT RENDER AS HTML`,
        `--------------------------------------------------------------------------------`,
        rawHtml
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
      ].join('\n');

      await r2.put(objectKey, sanitizedBanner, {
        httpMetadata: {
          contentType: 'text/plain; charset=utf-8',
          contentDisposition: `attachment; filename="${scanId}-snapshot.txt"`
        },
        customMetadata: {
          scan_id: scanId,
          target_url: targetUrl.slice(0, 512)
        }
      });

      return objectKey;
    } catch {
      return null;
    }
  }

  static async saveScanWithFindings(
    db: D1Database,
    report: ScanReportData,
    userId: string | null,
    r2SnapshotKey: string | null,
    caseNote: string | null
  ): Promise<void> {
    const statements: D1PreparedStatement[] = [];

    statements.push(
      db
        .prepare(
          `INSERT INTO scans (
            id, user_id, target_url, final_url, target_domain, protocol,
            http_status_code, redirect_count, redirect_chain_json,
            has_hsts, has_csp, has_x_frame_options,
            risk_score, risk_level, citizen_verdict_title, citizen_verdict_summary,
            source_preview_json, r2_snapshot_key, case_note,
            integrity_sha256, scan_duration_ms, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          report.scan_id,
          userId,
          report.target_url,
          report.final_url,
          report.target_domain,
          report.transport_audit.protocol,
          report.transport_audit.http_status_code,
          report.transport_audit.redirect_count,
          JSON.stringify(report.transport_audit.redirect_chain),
          report.transport_audit.security_headers.strict_transport_security ? 1 : 0,
          report.transport_audit.security_headers.content_security_policy ? 1 : 0,
          report.transport_audit.security_headers.x_frame_options ? 1 : 0,
          report.risk_score,
          report.risk_level,
          report.citizen_verdict.title,
          report.citizen_verdict.summary,
          JSON.stringify(report.source_preview),
          r2SnapshotKey,
          caseNote,
          report.integrity_sha256,
          report.duration_ms,
          report.scanned_at
        )
    );

    for (const f of report.findings) {
      statements.push(
        db
          .prepare(
            `INSERT INTO scan_findings (
              id, scan_id, rule_code, category, severity,
              line_number, column_number, dom_selector,
              citizen_explanation, technical_detail, code_snippet, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            f.id,
            report.scan_id,
            f.rule_code,
            f.category,
            f.severity,
            f.line_number,
            f.column_number,
            f.dom_selector,
            f.citizen_explanation,
            f.technical_detail,
            f.code_snippet,
            report.scanned_at
          )
      );
    }

    await db.batch(statements);
  }

  static async getScanById(db: D1Database, scanId: string): Promise<ScanReportData | null> {
    const scanRow = await db
      .prepare(`SELECT * FROM scans WHERE id = ? LIMIT 1`)
      .bind(scanId)
      .first<ScanRow>();

    if (!scanRow) {
      return null;
    }

    const findingsResult = await db
      .prepare(
        `SELECT id, scan_id, rule_code, category, severity,
                line_number, column_number, dom_selector,
                citizen_explanation, technical_detail, code_snippet
         FROM scan_findings
         WHERE scan_id = ?`
      )
      .bind(scanId)
      .all<FindingRow>();

    const findings: ScanFinding[] = (findingsResult.results ?? []).map((r) => ({
      id: r.id,
      rule_code: r.rule_code,
      category: r.category,
      severity: r.severity,
      line_number: r.line_number,
      column_number: r.column_number,
      dom_selector: r.dom_selector,
      citizen_explanation: r.citizen_explanation,
      technical_detail: r.technical_detail,
      code_snippet: r.code_snippet
    }));

    let redirectChain: RedirectHop[] = [];
    try {
      redirectChain = JSON.parse(scanRow.redirect_chain_json || '[]') as RedirectHop[];
    } catch {
      redirectChain = [];
    }

    let sourcePreview: SourcePreviewLine[] = [];
    try {
      sourcePreview = JSON.parse(scanRow.source_preview_json || '[]') as SourcePreviewLine[];
    } catch {
      sourcePreview = [];
    }

    const transportAudit = {
      protocol: scanRow.protocol,
      is_https: scanRow.protocol === 'https',
      http_status_code: scanRow.http_status_code,
      redirect_count: scanRow.redirect_count,
      redirect_chain: redirectChain,
      tls_verified: scanRow.protocol === 'https',
      content_type: 'text/html',
      response_bytes: 0,
      security_headers: {
        strict_transport_security: scanRow.has_hsts === 1,
        content_security_policy: scanRow.has_csp === 1,
        x_frame_options: scanRow.has_x_frame_options === 1
      }
    };

    const { evidencePayload } = await ScoringService.generateCanonicalIntegrity({
      scanId: scanRow.id,
      targetUrl: scanRow.target_url,
      finalUrl: scanRow.final_url,
      targetDomain: scanRow.target_domain,
      scannedAt: scanRow.created_at,
      transport: transportAudit,
      riskScore: scanRow.risk_score,
      riskLevel: scanRow.risk_level,
      findings
    });

    return {
      scan_id: scanRow.id,
      target_url: scanRow.target_url,
      final_url: scanRow.final_url,
      target_domain: scanRow.target_domain,
      scanned_at: scanRow.created_at,
      duration_ms: scanRow.scan_duration_ms,
      risk_score: scanRow.risk_score,
      risk_level: scanRow.risk_level,
      citizen_verdict: {
        title: scanRow.citizen_verdict_title,
        summary: scanRow.citizen_verdict_summary
      },
      transport_audit: transportAudit,
      findings,
      source_preview: sourcePreview,
      r2_snapshot_saved: Boolean(scanRow.r2_snapshot_key),
      case_note: scanRow.case_note,
      evidence_payload: evidencePayload,
      integrity_sha256: scanRow.integrity_sha256
    };
  }

  static async listUserHistory(
    db: D1Database,
    userId: string,
    filters: { page: number; limit: number; riskLevel?: string; search?: string }
  ): Promise<{
    items: Array<{
      scan_id: string;
      target_url: string;
      target_domain: string;
      risk_score: number;
      risk_level: RiskLevel;
      findings_count: number;
      scanned_at: string;
    }>;
    stats: {
      total_scans: number;
      threats_blocked: number;
    };
    pagination: {
      page: number;
      limit: number;
      total: number;
      total_pages: number;
    };
  }> {
    const conditions: string[] = ['s.user_id = ?'];
    const bindParams: Array<string | number> = [userId];

    if (filters.riskLevel && ['SAFE', 'WARNING', 'CRITICAL'].includes(filters.riskLevel)) {
      conditions.push('s.risk_level = ?');
      bindParams.push(filters.riskLevel);
    }

    if (filters.search && filters.search.trim().length > 0) {
      const term = `%${filters.search.trim().toLowerCase()}%`;
      conditions.push('(LOWER(s.target_domain) LIKE ? OR LOWER(s.target_url) LIKE ?)');
      bindParams.push(term, term);
    }

    const whereClause = conditions.join(' AND ');
    const offset = (filters.page - 1) * filters.limit;

    const countRow = await db
      .prepare(`SELECT COUNT(*) AS total FROM scans s WHERE ${whereClause}`)
      .bind(...bindParams)
      .first<{ total: number }>();

    const statsRow = await db
      .prepare(
        `SELECT
           COUNT(*) AS total_scans,
           SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS threats_blocked
         FROM scans
         WHERE user_id = ?`
      )
      .bind(userId)
      .first<{ total_scans: number; threats_blocked: number | null }>();

    const total = countRow?.total ?? 0;
    const totalPages = Math.max(1, Math.ceil(total / filters.limit));

    const listQuery = await db
      .prepare(
        `SELECT
           s.id AS scan_id,
           s.target_url,
           s.target_domain,
           s.risk_score,
           s.risk_level,
           s.created_at AS scanned_at,
           (SELECT COUNT(*) FROM scan_findings f WHERE f.scan_id = s.id) AS findings_count
         FROM scans s
         WHERE ${whereClause}
         ORDER BY s.created_at DESC
         LIMIT ? OFFSET ?`
      )
      .bind(...bindParams, filters.limit, offset)
      .all<{
        scan_id: string;
        target_url: string;
        target_domain: string;
        risk_score: number;
        risk_level: RiskLevel;
        findings_count: number;
        scanned_at: string;
      }>();

    return {
      items: listQuery.results ?? [],
      stats: {
        total_scans: statsRow?.total_scans ?? 0,
        threats_blocked: statsRow?.threats_blocked ?? 0
      },
      pagination: {
        page: filters.page,
        limit: filters.limit,
        total,
        total_pages: totalPages
      }
    };
  }

  static async deleteUserScan(db: D1Database, scanId: string, userId: string): Promise<void> {
    const ownerRow = await db
      .prepare(`SELECT id, user_id FROM scans WHERE id = ? LIMIT 1`)
      .bind(scanId)
      .first<{ id: string; user_id: string | null }>();

    if (!ownerRow) {
      throw new AppError(404, 'SCAN_NOT_FOUND', 'El reporte de análisis solicitado no existe');
    }

    if (ownerRow.user_id !== userId) {
      throw new AppError(
        403,
        'FORBIDDEN_RESOURCE',
        'No tienes permisos para eliminar un análisis que pertenece a otro usuario'
      );
    }

    await db.prepare(`DELETE FROM scans WHERE id = ? AND user_id = ?`).bind(scanId, userId).run();
  }

  static async createCommunityAlert(
    db: D1Database,
    params: {
      id: string;
      scanId: string;
      userId: string;
      targetDomain: string;
      riskScore: number;
      primaryRuleCode: string;
      channelReceived: AlertChannel;
      citizenNote: string | null;
      status: 'published' | 'under_review';
    }
  ): Promise<string> {
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

    await db
      .prepare(
        `INSERT INTO community_alerts (
          id, scan_id, reported_by_user_id, target_domain,
          risk_score, primary_rule_code, channel_received,
          citizen_note, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        params.id,
        params.scanId,
        params.userId,
        params.targetDomain,
        params.riskScore,
        params.primaryRuleCode,
        params.channelReceived,
        params.citizenNote,
        params.status,
        nowIso
      )
      .run();

    return nowIso;
  }

  static async listPublishedAlerts(
    db: D1Database,
    limit = 10
  ): Promise<
    Array<{
      alert_id: string;
      scan_id: string;
      target_domain: string;
      risk_score: number;
      primary_rule: string;
      channel_received: AlertChannel;
      reports_count: number;
      last_reported_at: string;
    }>
  > {
    const safeLimit = Math.max(1, Math.min(50, limit));
    const res = await db
      .prepare(
        `SELECT
           MAX(id) AS alert_id,
           MAX(scan_id) AS scan_id,
           target_domain,
           MAX(risk_score) AS risk_score,
           MAX(primary_rule_code) AS primary_rule,
           MAX(channel_received) AS channel_received,
           COUNT(*) AS reports_count,
           MAX(created_at) AS last_reported_at
         FROM community_alerts
         WHERE status = 'published'
         GROUP BY target_domain
         ORDER BY last_reported_at DESC
         LIMIT ?`
      )
      .bind(safeLimit)
      .all<{
        alert_id: string;
        scan_id: string;
        target_domain: string;
        risk_score: number;
        primary_rule: string;
        channel_received: AlertChannel;
        reports_count: number;
        last_reported_at: string;
      }>();

    return res.results ?? [];
  }
}
