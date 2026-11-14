import type { RequestContext } from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { CommercialRepository } from '../repositories/commercial.repository.ts';
import { CicpcRepository } from '../repositories/cicpc.repository.ts';
import { ScanRepository } from '../repositories/scan.repository.ts';
import { jsonResponse } from '../middlewares/security.middleware.ts';
import { RateLimitMiddleware } from '../middlewares/rateLimit.middleware.ts';
import { CommercialController } from './commercial.controller.ts';

export class CommunityController {
  static async listAlerts(rc: RequestContext): Promise<Response> {
    return await CommercialController.getLandingFeed(rc);
  }

  static async publishAlert(rc: RequestContext): Promise<Response> {
    if (!rc.user) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Inicia sesión o crea tu cuenta gratuita para publicar alertas comunitarias.',
          },
        },
        401
      );
    }

    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'community_publish',
      identifier: `usr:${rc.user.id}`,
      maxRequests: 10,
      windowSeconds: 3600,
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_JSON', message: 'Datos de alerta inválidos.' },
        },
        400
      );
    }

    const scanId = typeof body.scan_id === 'string' ? body.scan_id.trim() : '';
    const channelReceived =
      typeof body.channel_received === 'string' ? body.channel_received.trim() : 'whatsapp';
    const customLabel =
      typeof body.threat_category_label === 'string' ? body.threat_category_label.trim() : '';

    if (!scanId.startsWith('scn_')) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_SCAN', message: 'Debes indicar un escaneo válido.' },
        },
        400
      );
    }

    const scanRepo = new ScanRepository(rc.env.DB);
    const report = await scanRepo.findReportById(scanId);
    if (!report) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'SCAN_NOT_FOUND', message: 'No se encontró el reporte asociado.' },
        },
        404
      );
    }

    if (report.risk_score < 70) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'SCORE_BELOW_THRESHOLD',
            message:
              'Solo se publican en el Muro Comunitario enlaces con riesgo crítico verificado (puntaje >= 70).',
          },
        },
        400
      );
    }

    const defaultCategory = report.findings.some((f) => f.rule_code === 'CROSS_DOMAIN_FORM_ACTION')
      ? 'Formulario Clonado (Exfiltración Externa)'
      : report.findings.some((f) => f.rule_code === 'SUSPICIOUS_KEYLOGGER_EXFILTRATION')
      ? 'Espía de Teclado JS + Phishing'
      : ' Captura de Datos sin Cifrado HTTP';

    const commRepo = new CommercialRepository(rc.env.DB);
    const created = await commRepo.createCommunityAlert({
      id: CryptoService.generateUlid('alt'),
      scanId: report.scan_id,
      userId: rc.user.id,
      targetDomain: report.target_domain,
      riskScore: report.risk_score,
      threatCategoryLabel: customLabel || defaultCategory.trim(),
      channelReceived,
    });

    const cicpcRepo = new CicpcRepository(rc.env.DB);
    await cicpcRepo.registerNotificationOrComplaint({
      scanId: report.scan_id,
      reportedByUserId: rc.user.id,
      sourceType: 'COMMUNITY_ALERT',
      targetUrl: report.target_url,
      targetDomain: report.target_domain,
      riskScore: report.risk_score,
      riskLevel: report.risk_level,
      channelReceived,
      impersonatedEntity: customLabel || defaultCategory.trim(),
      incidentImpact: 'PREVENTIVE',
      citizenStatement: `Alerta comunitaria publicada por ciudadano verificado (${rc.user.alias}).`,
      reporterContact: rc.user.email,
    });

    await rc.env.KV_CACHE.delete('commercial:landing_feed');

    return jsonResponse(
      {
        success: true,
        message: '¡Gracias! Tu reporte ya protege a otros ciudadanos en el Muro de Amenazas en Vivo.',
        data: created,
      },
      201
    );
  }
}
