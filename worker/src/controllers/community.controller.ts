import { authenticateRequest } from '../middlewares/auth.middleware';
import { enforceRateLimit } from '../middlewares/rateLimit.middleware';
import { ScanRepository } from '../repositories/scan.repository';
import { Env, RequestContext } from '../types/env';
import { AlertChannel } from '../types/models';
import { AppError, errorResponse, jsonResponse, parseJsonBody } from '../utils/response';
import { generateUlid } from '../utils/ulid';

const VALID_CHANNELS = new Set<AlertChannel>([
  'whatsapp',
  'telegram',
  'sms',
  'email',
  'social',
  'web'
]);

export class CommunityController {
  static async publishAlert(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
    reqCtx: RequestContext
  ): Promise<Response> {
    const authErr = await authenticateRequest(request, env, reqCtx, 'required');
    if (authErr) return authErr;

    const rateLimited = await enforceRateLimit(env, reqCtx, 'community_write');
    if (rateLimited) return rateLimited;

    const body = await parseJsonBody<{
      scan_id?: unknown;
      channel_received?: unknown;
      citizen_note?: unknown;
    }>(request);

    const scanId = typeof body.scan_id === 'string' ? body.scan_id.trim() : '';
    const channel: AlertChannel =
      typeof body.channel_received === 'string' &&
      VALID_CHANNELS.has(body.channel_received as AlertChannel)
        ? (body.channel_received as AlertChannel)
        : 'web';
    const citizenNote =
      typeof body.citizen_note === 'string' && body.citizen_note.trim()
        ? body.citizen_note.trim().slice(0, 300)
        : null;

    if (!scanId) {
      throw new AppError(400, 'VALIDATION_ERROR', 'Debe especificar un scan_id válido');
    }

    const scan = await ScanRepository.getScanById(env.DB, scanId);
    if (!scan) {
      throw new AppError(404, 'SCAN_NOT_FOUND', 'El análisis forense referenciado no existe');
    }

    const primaryRule = scan.findings[0]?.rule_code || 'MANUAL_CITIZEN_REVIEW';
    const alertId = generateUlid('alt');

    // Enforce anti-defamation threshold: < 70 is queued as 'under_review' and rejected from immediate public feed
    if (scan.risk_score < 70) {
      await ScanRepository.createCommunityAlert(env.DB, {
        id: alertId,
        scanId: scan.scan_id,
        userId: reqCtx.user!.id,
        targetDomain: scan.target_domain,
        riskScore: scan.risk_score,
        primaryRuleCode: primaryRule,
        channelReceived: channel,
        citizenNote,
        status: 'under_review'
      });

      return errorResponse(
        400,
        'INSUFFICIENT_RISK_SCORE',
        'Solo los sitios con puntaje de riesgo crítico (>= 70) pueden publicarse como alerta inmediata. Tu reporte quedó marcado como "En revisión".',
        { status: 'under_review', alert_id: alertId }
      );
    }

    const createdAt = await ScanRepository.createCommunityAlert(env.DB, {
      id: alertId,
      scanId: scan.scan_id,
      userId: reqCtx.user!.id,
      targetDomain: scan.target_domain,
      riskScore: scan.risk_score,
      primaryRuleCode: primaryRule,
      channelReceived: channel,
      citizenNote,
      status: 'published'
    });

    return jsonResponse(
      {
        success: true,
        message: 'Alerta comunitaria publicada para proteger a otros ciudadanos',
        data: {
          alert_id: alertId,
          target_domain: scan.target_domain,
          risk_score: scan.risk_score,
          status: 'published',
          created_at: createdAt
        }
      },
      201
    );
  }

  static async listPublicAlerts(
    request: Request,
    env: Env
  ): Promise<Response> {
    const url = new URL(request.url);
    const limitRaw = Number.parseInt(url.searchParams.get('limit') || '10', 10);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(30, limitRaw)) : 10;

    const alerts = await ScanRepository.listPublishedAlerts(env.DB, limit);

    return jsonResponse({
      success: true,
      data: {
        alerts
      }
    });
  }
}
