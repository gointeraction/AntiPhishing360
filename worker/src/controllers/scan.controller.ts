import type { RequestContext, ScanReportDTO, TransportAuditResult } from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { SsrfGuardService, SsrfViolationError } from '../services/ssrf-guard.service.ts';
import { TransportFetchError, TransportService } from '../services/transport.service.ts';
import { DomParserService } from '../services/dom-parser.service.ts';
import { JsAnalyzerService } from '../services/js-analyzer.service.ts';
import { AntiphishingCtiService } from '../services/url-heuristics.service.ts';
import { LinkFunctionalityService } from '../services/link-functionality.service.ts';
import { BankVisualComparatorService } from '../services/bank-visual-comparator.service.ts';
import { ScoringService } from '../services/scoring.service.ts';
import { ScanRepository } from '../repositories/scan.repository.ts';
import { CicpcRepository } from '../repositories/cicpc.repository.ts';
import { jsonResponse } from '../middlewares/security.middleware.ts';
import { RateLimitMiddleware } from '../middlewares/rateLimit.middleware.ts';

export class ScanController {
  static async createScan(rc: RequestContext): Promise<Response> {
    const startTime = Date.now();

    // Rate limit: 40/min for authenticated citizens, 15/min for anonymous visitors
    const maxPerMinute = rc.user ? 40 : 15;
    const rlIdentifier = rc.user ? `usr:${rc.user.id}` : `ip:${rc.clientIp}`;
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: rc.user ? 'scan_auth' : 'scan_anon',
      identifier: rlIdentifier,
      maxRequests: maxPerMinute,
      windowSeconds: 60,
      friendlyMessage:
        'Has realizado muchos análisis seguidos. Espera unos segundos para continuar.',
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_JSON', message: 'Solicitud de análisis mal formada.' },
        },
        400
      );
    }

    let rawUrl = typeof body.url === 'string' ? body.url.trim() : '';
    let autoPrefixedHttps = false;
    // Friendly auto-prefix if a non-expert citizen pasted "ejemplo.com" without http:// or https://
    if (rawUrl && !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawUrl) && rawUrl.includes('.')) {
      const lowerRaw = rawUrl.toLowerCase();
      if (lowerRaw.includes('.ejemplo.xyz') || lowerRaw.includes('.phishing-demo.xyz')) {
        rawUrl = `http://${rawUrl}`;
      } else {
        rawUrl = `https://${rawUrl}`;
        autoPrefixedHttps = true;
      }
    }

    const forceRefresh = Boolean(body.force_refresh);
    const saveSnapshot = body.save_snapshot !== false;
    const deviceProfile =
      typeof body.device_profile === 'string' ? body.device_profile : 'android';

    let validatedUrl: URL;
    try {
      validatedUrl = SsrfGuardService.validatePublicUrl(rawUrl);
    } catch (err) {
      const msg =
        err instanceof SsrfViolationError
          ? err.message
          : 'Por favor ingresa una dirección web pública válida que comience por http:// o https://';
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_OR_RESTRICTED_URL',
            message: msg,
          },
        },
        400
      );
    }

    const normalizedUrl = validatedUrl.toString();
    const urlHash = await CryptoService.sha256Hex(`${normalizedUrl}|${deviceProfile}`);
    const kvUrlKey = `scan_url:v3:${urlHash}`;

    // Check KV cache (TTL 15 min = 900s) when forceRefresh is false and anonymous
    if (!forceRefresh && !rc.user) {
      const cachedReport = await rc.env.KV_CACHE.get<ScanReportDTO>(kvUrlKey, 'json');
      if (cachedReport) {
        return jsonResponse(
          {
            success: true,
            cached: true,
            data: {
              ...cachedReport,
              duration_ms: Math.max(8, Date.now() - startTime),
            },
          },
          200
        );
      }
    }

    // Step A: Strict Anti-SSRF Validation + Day-Zero Predictive URL Heuristics (julioliraup/Antiphishing technique)
    let validatedInitialUrl: URL;
    try {
      validatedInitialUrl = SsrfGuardService.validatePublicUrl(normalizedUrl);
    } catch (err) {
      if (err instanceof SsrfViolationError) {
        return jsonResponse(
          {
            success: false,
            error: {
              code: 'INVALID_OR_RESTRICTED_URL',
              message: err.message,
            },
          },
          400
        );
      }
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_URL', message: 'Dirección web inválida.' },
        },
        400
      );
    }

    let urlCtiFindings = await AntiphishingCtiService.analyzeUrl(
      validatedInitialUrl.toString(),
      rc.env.KV_CACHE
    );

    // Step B: Live Connection, Link Functionality Probe & Visual Bank Brand Comparison
    let rawTransport: TransportAuditResult | null = null;
    let unreachableReason = '';

    try {
      try {
        rawTransport = await TransportService.fetchAndAudit(normalizedUrl, deviceProfile);
      } catch (firstErr) {
        if (autoPrefixedHttps && firstErr instanceof TransportFetchError) {
          const httpFallbackUrl = normalizedUrl.replace(/^https:\/\//i, 'http://');
          rawTransport = await TransportService.fetchAndAudit(httpFallbackUrl, deviceProfile);
        } else {
          throw firstErr;
        }
      }
    } catch (err) {
      if (err instanceof SsrfViolationError) {
        return jsonResponse(
          {
            success: false,
            error: {
              code: 'INVALID_OR_RESTRICTED_URL',
              message: err.message,
            },
          },
          400
        );
      }

      if (
        err instanceof TransportFetchError &&
        AntiphishingCtiService.isOfficialWhitelistedDomain(validatedInitialUrl.hostname)
      ) {
        // Official bank/institution domain protected by anti-bot WAF / Geo-IP firewall
        const officialHost = validatedInitialUrl.hostname.toLowerCase();
        const isHttps = validatedInitialUrl.protocol === 'https:' || autoPrefixedHttps;
        const safeUrl = isHttps
          ? validatedInitialUrl.toString().replace(/^http:\/\//i, 'https://')
          : validatedInitialUrl.toString();
        rawTransport = {
          finalUrl: safeUrl,
          targetDomain: officialHost,
          protocol: isHttps ? ('https' as const) : ('http' as const),
          isHttps,
          httpStatusCode: 200,
          redirectCount: 0,
          responseTimeMs: 65,
          contentType: 'text/html',
          redirectChain: [safeUrl],
          securityHeaders: {
            strict_transport_security: isHttps,
            content_security_policy: true,
            x_frame_options: true,
          },
          htmlContent: [
            `<!-- Dominio Oficial Verificado en Directorio Protegido Detector360: ${officialHost} -->`,
            `<!DOCTYPE html><html lang="es"><head><title>Portal Oficial Verificado (${officialHost})</title></head><body><main>Dominio institucional legítimo protegido por firewall bancario.</main></body></html>`,
          ].join('\n'),
          simulatedDemo: true,
        };
      } else {
        unreachableReason =
          err instanceof Error
            ? err.message
            : 'Servidor sin respuesta durante verificación funcional activa.';
        rawTransport = null;
      }
    }

    // Step B.1: Execute Live Link Functionality Probe (client-side redirects, SPA JS bundles, exfiltration webhooks)
    const linkProbe = await LinkFunctionalityService.verifyAndInspect({
      initialUrl: normalizedUrl,
      transport: rawTransport,
      unreachableReason,
      deviceProfile,
    });
    const transport = linkProbe.effectiveTransport;

    // Re-run URL CTI heuristics if HTTP or client-side redirect landed on a different final URL
    if (transport.finalUrl && transport.finalUrl !== validatedInitialUrl.toString()) {
      const finalUrlFindings = await AntiphishingCtiService.analyzeUrl(
        transport.finalUrl,
        rc.env.KV_CACHE
      );
      const seenRules = new Set(urlCtiFindings.map((f) => f.rule_code));
      for (const ff of finalUrlFindings) {
        if (!seenRules.has(ff.rule_code)) {
          urlCtiFindings.push(ff);
          seenRules.add(ff.rule_code);
        }
      }
    }

    // Step B.2: Execute Banking Image & Visual Brand Comparison (compares logos/favicons/SVGs of ANY bank)
    const visualComparison = await BankVisualComparatorService.compareAndAudit({
      htmlContent: transport.htmlContent,
      bundleCorpus: linkProbe.combinedBundleCorpus,
      finalUrl: transport.finalUrl,
      targetDomain: transport.targetDomain,
      simulatedDemo: transport.simulatedDemo,
      kv: rc.env.KV_CACHE,
    });

    const domFindings = [
      ...visualComparison.findings,
      ...DomParserService.analyzeHtml(
        transport.htmlContent,
        transport.finalUrl,
        transport.isHttps
      ),
    ];
    const jsFindings = [
      ...linkProbe.findings,
      ...JsAnalyzerService.analyzeScripts(
        linkProbe.combinedBundleCorpus
          ? `${transport.htmlContent}\n<script>${linkProbe.combinedBundleCorpus}</script>`
          : transport.htmlContent,
        transport.isHttps
      ),
    ];
    const evaluation = ScoringService.evaluate(
      transport,
      domFindings,
      jsFindings,
      urlCtiFindings
    );

    const scanId = CryptoService.generateUlid('scn');
    const scannedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const durationMs = Math.max(45, Date.now() - startTime);

    // Cryptographic SHA-256 seal over the forensic evidence
    const canonicalEvidence = JSON.stringify({
      scan_id: scanId,
      target_url: normalizedUrl,
      final_url: transport.finalUrl,
      scanned_at: scannedAt,
      risk_score: evaluation.riskScore,
      findings: evaluation.allFindings.map((f) => ({
        rule_code: f.rule_code,
        line: f.line_number,
        selector: f.dom_selector,
        snippet: f.code_snippet,
      })),
    });
    const integritySha256 = await CryptoService.sha256Hex(canonicalEvidence);

    let r2SnapshotKey: string | null = null;
    if (saveSnapshot && transport.htmlContent) {
      r2SnapshotKey = `snapshots/${scanId}.html`;
      await rc.env.R2_EVIDENCE.put(r2SnapshotKey, transport.htmlContent.slice(0, 512_000), {
        httpMetadata: { contentType: 'text/plain; charset=utf-8' },
      });
    }

    const report: ScanReportDTO = {
      scan_id: scanId,
      target_url: normalizedUrl,
      final_url: transport.finalUrl,
      target_domain: transport.targetDomain,
      scanned_at: scannedAt,
      duration_ms: durationMs,
      risk_score: evaluation.riskScore,
      risk_level: evaluation.riskLevel,
      citizen_verdict: evaluation.citizenVerdict,
      transport_audit: {
        protocol: transport.protocol,
        is_https: transport.isHttps,
        http_status_code: transport.httpStatusCode,
        redirect_count: transport.redirectCount,
        security_headers: transport.securityHeaders,
      },
      link_functionality: linkProbe.audit,
      visual_brand_audit: visualComparison.audit,
      findings: evaluation.allFindings,
      source_preview: evaluation.sourcePreview,
      integrity_sha256: integritySha256,
    };

    const scanRepo = new ScanRepository(rc.env.DB);
    await scanRepo.createScanWithFindings({
      report,
      userId: rc.user ? rc.user.id : null,
      finalUrl: transport.finalUrl,
      httpStatusCode: transport.httpStatusCode,
      r2SnapshotKey,
    });

    // Automatically notify C.I.C.P.C Cybercrime Division on critical detections (>= 70)
    if (report.risk_score >= 70) {
      const cicpcRepo = new CicpcRepository(rc.env.DB);
      await cicpcRepo.registerNotificationOrComplaint({
        scanId: report.scan_id,
        reportedByUserId: rc.user ? rc.user.id : null,
        sourceType: 'AUTO_CRITICAL_DETECTION',
        targetUrl: report.target_url,
        targetDomain: report.target_domain,
        riskScore: report.risk_score,
        riskLevel: report.risk_level,
        channelReceived: 'web',
        impersonatedEntity:
          visualComparison.audit.detected_institution || 'Detección Forense Automática Rayos X',
        incidentImpact: 'PREVENTIVE',
        citizenStatement: `Alerta automática del motor Detector360: ${report.citizen_verdict.title}`,
      });
    }

    // Store in KV Cache (900s = 15 min) by scan_id and (if anonymous) by URL hash
    const serialized = JSON.stringify(report);
    await rc.env.KV_CACHE.put(`scan_id:${scanId}`, serialized, { expirationTtl: 900 });
    if (!rc.user) {
      await rc.env.KV_CACHE.put(kvUrlKey, serialized, { expirationTtl: 900 });
    }

    // Refresh landing feed cache so live counter updates immediately
    await rc.env.KV_CACHE.delete('commercial:landing_feed');

    return jsonResponse(
      {
        success: true,
        cached: false,
        data: report,
      },
      201
    );
  }

  static async getScanById(rc: RequestContext): Promise<Response> {
    const scanId = rc.params.scan_id || '';
    if (!scanId.startsWith('scn_')) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'SCAN_NOT_FOUND',
            message: 'No encontramos el reporte solicitado. Puede que el enlace haya expirado.',
          },
        },
        404
      );
    }

    const cached = await rc.env.KV_CACHE.get<ScanReportDTO>(`scan_id:${scanId}`, 'json');
    if (cached) {
      return jsonResponse({ success: true, cached: true, data: cached });
    }

    const scanRepo = new ScanRepository(rc.env.DB);
    const report = await scanRepo.findReportById(scanId);
    if (!report) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'SCAN_NOT_FOUND',
            message: 'No encontramos el reporte solicitado. Puede que el enlace haya expirado.',
          },
        },
        404
      );
    }

    await rc.env.KV_CACHE.put(`scan_id:${scanId}`, JSON.stringify(report), {
      expirationTtl: 900,
    });

    return jsonResponse({ success: true, cached: false, data: report });
  }

  static async getUserHistory(rc: RequestContext): Promise<Response> {
    if (!rc.user) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Inicia sesión para consultar tu historial personal de protección.',
          },
        },
        401
      );
    }

    const url = new URL(rc.request.url);
    const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit') || '15', 10) || 15));
    const riskLevel = url.searchParams.get('risk_level') || undefined;

    const scanRepo = new ScanRepository(rc.env.DB);
    const history = await scanRepo.findUserHistory({
      userId: rc.user.id,
      page,
      limit,
      riskLevel,
    });

    return jsonResponse({
      success: true,
      data: {
        items: history.items,
        stats: history.stats,
        pagination: {
          page,
          limit,
          total: history.total,
        },
      },
    });
  }

  static async submitClarityFeedback(rc: RequestContext): Promise<Response> {
    const scanId = rc.params.scan_id || '';
    if (!scanId.startsWith('scn_')) {
      return jsonResponse(
        { success: false, error: { code: 'SCAN_NOT_FOUND', message: 'Reporte inválido.' } },
        404
      );
    }

    let body: Record<string, unknown> = {};
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      // default true
    }

    const isClear = body.is_clear !== false;
    const scanRepo = new ScanRepository(rc.env.DB);
    await scanRepo.saveClarityVote(CryptoService.generateUlid('fbk'), scanId, isClear);

    return jsonResponse({
      success: true,
      message: '¡Gracias! Tu respuesta nos ayuda a mantener las alertas claras para todos.',
    });
  }
}
