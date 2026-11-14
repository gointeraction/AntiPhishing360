import { authenticateRequest } from '../middlewares/auth.middleware';
import { enforceRateLimit } from '../middlewares/rateLimit.middleware';
import { ScanRepository } from '../repositories/scan.repository';
import { CryptoService } from '../services/crypto.service';
import { DomParserService } from '../services/dom-parser.service';
import { JsAnalyzerService } from '../services/js-analyzer.service';
import { ScoringService } from '../services/scoring.service';
import { SsrfGuardService } from '../services/ssrf-guard.service';
import { TransportService } from '../services/transport.service';
import { Env, RequestContext } from '../types/env';
import { ScanFinding, ScanReportData, UserAgentProfile } from '../types/models';
import { AppError, jsonResponse, parseJsonBody } from '../utils/response';
import { generateUlid } from '../utils/ulid';

const VALID_PROFILES = new Set<UserAgentProfile>([
  'mobile_android',
  'mobile_ios',
  'desktop_chrome'
]);

export class ScanController {
  static async createScan(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const startTime = Date.now();

    // Optional authentication so logged-in citizens link scans to their history
    await authenticateRequest(request, env, reqCtx, 'optional');

    const rateLimited = await enforceRateLimit(env, reqCtx, 'scan');
    if (rateLimited) return rateLimited;

    const body = await parseJsonBody<{
      url?: unknown;
      force_refresh?: unknown;
      save_snapshot?: unknown;
      user_agent_profile?: unknown;
      case_note?: unknown;
    }>(request);

    const rawUrl = typeof body.url === 'string' ? body.url.trim() : '';
    const forceRefresh = body.force_refresh === true;
    const saveSnapshot = body.save_snapshot === true;
    const profile: UserAgentProfile =
      typeof body.user_agent_profile === 'string' &&
      VALID_PROFILES.has(body.user_agent_profile as UserAgentProfile)
        ? (body.user_agent_profile as UserAgentProfile)
        : 'mobile_android';
    const caseNote =
      typeof body.case_note === 'string' && body.case_note.trim()
        ? body.case_note.trim().slice(0, 500)
        : null;

    // Fast syntax & IP literal validation before checking KV cache
    const preValidatedUrl = await SsrfGuardService.validateTargetUrl(rawUrl, false);
    const normalizedTargetUrl = preValidatedUrl.toString();
    const cacheKeyHash = await CryptoService.sha256Hex(`${normalizedTargetUrl}|${profile}`);

    if (!forceRefresh) {
      const cachedReport = await ScanRepository.getCachedScan(env.KV_CACHE, cacheKeyHash);
      if (cachedReport) {
        // If citizen is logged in, persist a user-linked scan copy in D1 so it appears in Mi Historial
        if (reqCtx.user) {
          const clonedScanId = generateUlid('scn');
          const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
          const clonedFindings: ScanFinding[] = cachedReport.findings.map((f) => ({
            ...f,
            id: generateUlid('fnd')
          }));
          const { evidencePayload, integritySha256 } =
            await ScoringService.generateCanonicalIntegrity({
              scanId: clonedScanId,
              targetUrl: cachedReport.target_url,
              finalUrl: cachedReport.final_url,
              targetDomain: cachedReport.target_domain,
              scannedAt: nowIso,
              transport: cachedReport.transport_audit,
              riskScore: cachedReport.risk_score,
              riskLevel: cachedReport.risk_level,
              findings: clonedFindings
            });

          const userLinkedReport: ScanReportData = {
            ...cachedReport,
            scan_id: clonedScanId,
            scanned_at: nowIso,
            duration_ms: Math.max(1, Date.now() - startTime),
            findings: clonedFindings,
            case_note: caseNote,
            evidence_payload: evidencePayload,
            integrity_sha256: integritySha256
          };

          await ScanRepository.saveScanWithFindings(
            env.DB,
            userLinkedReport,
            reqCtx.user.id,
            null,
            caseNote
          );

          return jsonResponse(
            {
              success: true,
              cached: true,
              data: userLinkedReport
            },
            200
          );
        }

        return jsonResponse(
          {
            success: true,
            cached: true,
            data: cachedReport
          },
          200
        );
      }
    }

    // Live Forensic Pipeline Execution:
    // 1. SSRF + DoH Guard + Transport & Redirect & Header Audit
    const transportResult = await TransportService.fetchAndAudit(normalizedTargetUrl, profile);

    // 2. Line-Indexed Static DOM (<form> & <input>) Analysis
    const domResult = DomParserService.analyzeHtml(
      transportResult.htmlContent,
      transportResult.finalUrl
    );

    // 3. Static JavaScript Exfiltration & Obfuscation Analysis
    const jsFindings = JsAnalyzerService.analyzeScripts(
      domResult.indexMap,
      transportResult.finalUrl
    );

    // 4. Risk Scoring (0-100) + Verdict + Source Preview + Canonical SHA-256
    const allFindings: ScanFinding[] = [
      ...transportResult.findings,
      ...domResult.findings,
      ...jsFindings
    ];

    const { sortedFindings, riskScore, riskLevel, citizenVerdict } =
      ScoringService.evaluateRisk(allFindings, transportResult.audit);

    const sourcePreview = ScoringService.buildSourcePreview(domResult.indexMap, sortedFindings);

    const scanId = generateUlid('scn');
    const scannedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const targetDomain = transportResult.finalUrl.hostname.toLowerCase();

    const { evidencePayload, integritySha256 } =
      await ScoringService.generateCanonicalIntegrity({
        scanId,
        targetUrl: normalizedTargetUrl,
        finalUrl: transportResult.finalUrl.toString(),
        targetDomain,
        scannedAt,
        transport: transportResult.audit,
        riskScore,
        riskLevel,
        findings: sortedFindings
      });

    // 5. Optional Sanitized Snapshot in Cloudflare R2
    let r2SnapshotKey: string | null = null;
    if (saveSnapshot) {
      r2SnapshotKey = await ScanRepository.saveSanitizedSnapshot(
        env.R2_EVIDENCE,
        scanId,
        normalizedTargetUrl,
        transportResult.htmlContent
      );
    }

    const durationMs = Math.max(1, Date.now() - startTime);

    const reportData: ScanReportData = {
      scan_id: scanId,
      target_url: normalizedTargetUrl,
      final_url: transportResult.finalUrl.toString(),
      target_domain: targetDomain,
      scanned_at: scannedAt,
      duration_ms: durationMs,
      risk_score: riskScore,
      risk_level: riskLevel,
      citizen_verdict: citizenVerdict,
      transport_audit: transportResult.audit,
      findings: sortedFindings,
      source_preview: sourcePreview,
      r2_snapshot_saved: Boolean(r2SnapshotKey),
      case_note: caseNote,
      evidence_payload: evidencePayload,
      integrity_sha256: integritySha256
    };

    // 6. Persist in Cloudflare D1 & Cache in Cloudflare KV (TTL 15 min = 900s)
    await ScanRepository.saveScanWithFindings(
      env.DB,
      reportData,
      reqCtx.user?.id ?? null,
      r2SnapshotKey,
      caseNote
    );

    await ScanRepository.setCachedScan(env.KV_CACHE, cacheKeyHash, reportData, 900);

    return jsonResponse(
      {
        success: true,
        cached: false,
        data: reportData
      },
      201
    );
  }

  static async getScanById(
    _request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const scanId = (reqCtx.params.scan_id || '').trim();
    if (!scanId || !/^scn_[0-9A-Z]{26}$/.test(scanId)) {
      throw new AppError(
        404,
        'SCAN_NOT_FOUND',
        'El reporte de análisis solicitado no existe o ha expirado'
      );
    }

    const scanReport = await ScanRepository.getScanById(env.DB, scanId);
    if (!scanReport) {
      throw new AppError(
        404,
        'SCAN_NOT_FOUND',
        'El reporte de análisis solicitado no existe o ha expirado'
      );
    }

    return jsonResponse({
      success: true,
      data: scanReport
    });
  }

  static async getUserHistory(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const authErr = await authenticateRequest(request, env, reqCtx, 'required');
    if (authErr) return authErr;

    const url = new URL(request.url);
    const pageRaw = Number.parseInt(url.searchParams.get('page') || '1', 10);
    const limitRaw = Number.parseInt(url.searchParams.get('limit') || '20', 10);
    const riskLevel = url.searchParams.get('risk_level') || undefined;
    const search = url.searchParams.get('search') || undefined;

    const page = Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1;
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(50, limitRaw)) : 20;

    const historyData = await ScanRepository.listUserHistory(env.DB, reqCtx.user!.id, {
      page,
      limit,
      riskLevel,
      search
    });

    return jsonResponse({
      success: true,
      data: historyData
    });
  }

  static async deleteUserScan(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const authErr = await authenticateRequest(request, env, reqCtx, 'required');
    if (authErr) return authErr;

    const scanId = (reqCtx.params.scan_id || '').trim();
    if (!scanId) {
      throw new AppError(404, 'SCAN_NOT_FOUND', 'Identificador de escaneo inválido');
    }

    await ScanRepository.deleteUserScan(env.DB, scanId, reqCtx.user!.id);

    return jsonResponse({
      success: true,
      message: 'Registro eliminado de tu historial personal'
    });
  }
}
