import type { CicpcIncidentImpact, RequestContext, RiskLevel, ScanReportDTO } from '../types.ts';
import { jsonResponse } from '../middlewares/security.middleware.ts';
import { RateLimitMiddleware } from '../middlewares/rateLimit.middleware.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { SeniorProtectionService } from '../services/senior-protection.service.ts';
import { SeniorRepository } from '../repositories/senior.repository.ts';
import { ScanRepository } from '../repositories/scan.repository.ts';
import { CicpcRepository } from '../repositories/cicpc.repository.ts';

export class SeniorController {
  /**
   * POST /api/v1/senior/analyze-message
   * Analiza mensajes completos de WhatsApp / SMS o textos de capturas de pantalla (OCR)
   */
  static async analyzeMessage(rc: RequestContext): Promise<Response> {
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'senior_msg',
      identifier: `ip:${rc.clientIp}`,
      maxRequests: 25,
      windowSeconds: 60,
      friendlyMessage: 'Por favor espera unos segundos antes de analizar otro mensaje.',
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_JSON', message: 'Formato de mensaje inválido.' },
        },
        400
      );
    }

    const messageText = typeof body.message_text === 'string' ? body.message_text.trim() : '';
    if (messageText.length < 6) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'MESSAGE_TOO_SHORT',
            message: 'Pega el mensaje completo o sube la captura para poder revisarlo.',
          },
        },
        400
      );
    }

    const analysis = await SeniorProtectionService.analyzeSeniorMessage(messageText.slice(0, 4000));

    // Persistir un reporte forense trazable en `scans` para que pueda consultarse por Ángel Guardián o C.I.C.P.C
    let domain = 'mensaje-whatsapp-sms.local';
    try {
      domain = new URL(analysis.primary_url).hostname;
    } catch {
      domain = 'mensaje-whatsapp-sms.local';
    }

    const syntheticLines = messageText
      .slice(0, 1200)
      .split(/\r?\n/)
      .slice(0, 18)
      .map((line, idx) => ({
        line: idx + 1,
        content: line,
        has_finding: analysis.risk_level !== 'SAFE' && idx < 4,
      }));

    const integrityHash = await CryptoService.sha256Hex(
      `${analysis.scan_id}|${messageText}|${analysis.risk_score}`
    );

    const syntheticReport: ScanReportDTO = {
      scan_id: analysis.scan_id,
      target_url: analysis.primary_url,
      final_url: analysis.primary_url,
      target_domain: domain,
      scanned_at: analysis.analyzed_at,
      duration_ms: 45,
      risk_score: analysis.risk_score,
      risk_level: analysis.risk_level,
      citizen_verdict: analysis.citizen_verdict,
      transport_audit: {
        protocol: analysis.primary_url.startsWith('https://') ? 'https' : 'http',
        is_https: analysis.primary_url.startsWith('https://'),
        http_status_code: 200,
        redirect_count: 0,
        security_headers: {
          strict_transport_security: false,
          content_security_policy: false,
          x_frame_options: false,
        },
      },
      findings: analysis.findings,
      source_preview: syntheticLines,
      integrity_sha256: integrityHash,
    };

    const scanRepo = new ScanRepository(rc.env.DB);
    await scanRepo.createScanWithFindings({
      report: syntheticReport,
      userId: rc.user ? rc.user.id : null,
      finalUrl: analysis.primary_url,
      httpStatusCode: 200,
      r2SnapshotKey: null,
    });

    if (analysis.risk_level === 'CRITICAL') {
      const cicpcRepo = new CicpcRepository(rc.env.DB);
      await cicpcRepo
        .registerNotificationOrComplaint({
          scanId: analysis.scan_id,
          reportedByUserId: rc.user ? rc.user.id : null,
          sourceType: 'AUTO_CRITICAL_DETECTION',
          targetUrl: analysis.primary_url,
          targetDomain: domain,
          riskScore: analysis.risk_score,
          riskLevel: analysis.risk_level,
          channelReceived: 'whatsapp',
          impersonatedEntity: analysis.impersonated_entity,
          citizenStatement: `Detección en Analizador Adulto Mayor (${analysis.detected_scam_type}): "${messageText.slice(0, 240)}"`,
        })
        .catch(() => {});
    }

    return jsonResponse({ success: true, data: analysis }, 201);
  }

  /**
   * GET /api/v1/senior/directory?q=...&category=...
   * Directorio Blanco Verificado de Bancos, Organismos Públicos y Empresas de Envío
   */
  static async listDirectory(rc: RequestContext): Promise<Response> {
    const url = new URL(rc.request.url);
    const query = url.searchParams.get('q') || '';
    const category = url.searchParams.get('category') || 'ALL';

    const repo = new SeniorRepository(rc.env.DB);
    const items = await repo.searchVerifiedDirectory({ query, category });

    return jsonResponse({
      success: true,
      data: {
        total: items.length,
        items,
      },
    });
  }

  /**
   * GET /api/v1/senior/simulator
   * Simulador de Entrenamiento Ligero (3 Preguntas con Casos Reales)
   */
  static async getSimulatorQuestions(): Promise<Response> {
    const questions = SeniorProtectionService.getTrainingSimulatorQuestions();
    return jsonResponse({
      success: true,
      data: {
        total: questions.length,
        questions,
      },
    });
  }

  /**
   * POST /api/v1/senior/guardian/ask
   * Crea una consulta "Preguntar a mi Hijo / Familiar de Confianza" o Alerta Crítica Automática
   */
  static async createGuardianAlert(rc: RequestContext): Promise<Response> {
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'guardian_ask',
      identifier: `ip:${rc.clientIp}`,
      maxRequests: 20,
      windowSeconds: 60,
      friendlyMessage: 'Espera unos segundos antes de enviar otra consulta familiar.',
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        { success: false, error: { code: 'INVALID_JSON', message: 'Solicitud inválida.' } },
        400
      );
    }

    const seniorName =
      typeof body.senior_name === 'string' && body.senior_name.trim()
        ? body.senior_name.trim()
        : 'Mamá / Papá';
    const guardianName =
      typeof body.guardian_name === 'string' && body.guardian_name.trim()
        ? body.guardian_name.trim()
        : 'Hijo / Familiar de Confianza';
    const guardianPhone =
      typeof body.guardian_phone === 'string' ? body.guardian_phone.trim() : '';
    const scanId = typeof body.scan_id === 'string' ? body.scan_id.trim() : null;
    const targetUrl = typeof body.target_url === 'string' ? body.target_url.trim() : '';
    const messageExcerpt =
      typeof body.message_excerpt === 'string' ? body.message_excerpt.trim() : '';
    const alertMode =
      body.alert_mode === 'AUTO_CRITICAL_ALERT' ? 'AUTO_CRITICAL_ALERT' : 'ASK_GUARDIAN';
    const riskScore = typeof body.risk_score === 'number' ? body.risk_score : 75;
    const rawLevel = typeof body.risk_level === 'string' ? body.risk_level : 'WARNING';
    const riskLevel: RiskLevel =
      rawLevel === 'CRITICAL' || rawLevel === 'SAFE' ? rawLevel : 'WARNING';

    if (!targetUrl && !messageExcerpt) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'MISSING_CONTENT',
            message: 'Indica el enlace o mensaje que deseas consultar con tu familiar.',
          },
        },
        400
      );
    }

    const repo = new SeniorRepository(rc.env.DB);
    const consultation = await repo.createGuardianConsultation({
      scanId,
      seniorName,
      guardianName,
      guardianPhone,
      alertMode,
      targetUrl,
      messageExcerpt,
      riskScore,
      riskLevel,
    });

    const origin = new URL(rc.request.url).origin;
    const reviewUrl = `${origin}/guardian?token=${encodeURIComponent(consultation.token)}`;
    const digitsOnly = guardianPhone.replace(/[^\d]/g, '');

    const waPrefix =
      alertMode === 'AUTO_CRITICAL_ALERT'
        ? `ALERTA ESCUDO FAMILIAR DETECTOR360: ${seniorName} acaba de revisar un mensaje o enlace ROJO PELIGROSO (${riskScore}/100).`
        : `Hola ${guardianName}, soy ${seniorName}. Me llegó esto al teléfono y tengo dudas. ¿Me ayudas revisándolo aquí y me dices si es seguro o lo borro?`;

    const waText = `${waPrefix}\n\nResponder en 1 toque: ${reviewUrl}`;
    const whatsappShareUrl = digitsOnly
      ? `https://wa.me/${digitsOnly}?text=${encodeURIComponent(waText)}`
      : `https://wa.me/?text=${encodeURIComponent(waText)}`;

    return jsonResponse(
      {
        success: true,
        data: {
          consultation,
          review_url: reviewUrl,
          whatsapp_share_url: whatsappShareUrl,
        },
      },
      201
    );
  }

  /**
   * GET /api/v1/senior/guardian/:token
   * Consulta el estado de revisión familiar (para la vista del hijo/familiar y el teléfono del abuelo)
   */
  static async getGuardianConsultation(rc: RequestContext): Promise<Response> {
    const token = rc.params.token || '';
    if (!token) {
      return jsonResponse(
        { success: false, error: { code: 'MISSING_TOKEN', message: 'Código familiar faltante.' } },
        400
      );
    }

    const repo = new SeniorRepository(rc.env.DB);
    const consultation = await repo.getConsultationByToken(token);
    if (!consultation) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'CONSULTATION_NOT_FOUND',
            message: 'No encontramos esta consulta familiar.',
          },
        },
        404
      );
    }

    return jsonResponse({
      success: true,
      data: { consultation },
    });
  }

  /**
   * POST /api/v1/senior/guardian/:token/reply
   * El hijo / familiar responde en 1 toque: "SAFE_APPROVED" (Es seguro) o "DANGER_DELETE" (Bórralo ya)
   */
  static async replyGuardianConsultation(rc: RequestContext): Promise<Response> {
    const token = rc.params.token || '';
    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        { success: false, error: { code: 'INVALID_JSON', message: 'Respuesta inválida.' } },
        400
      );
    }

    const rawDecision = typeof body.decision === 'string' ? body.decision.toUpperCase() : '';
    if (rawDecision !== 'SAFE_APPROVED' && rawDecision !== 'DANGER_DELETE') {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_DECISION',
            message: 'Selecciona si el mensaje es seguro o si debe borrarlo de inmediato.',
          },
        },
        400
      );
    }

    const note = typeof body.note === 'string' ? body.note.trim() : '';
    const repo = new SeniorRepository(rc.env.DB);
    const updated = await repo.replyToConsultation({
      token,
      decision: rawDecision,
      note,
    });

    if (!updated) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'CONSULTATION_NOT_FOUND', message: 'Consulta familiar no encontrada.' },
        },
        404
      );
    }

    return jsonResponse({
      success: true,
      message:
        rawDecision === 'DANGER_DELETE'
          ? 'Respuesta enviada: Se le indicó a tu familiar que BORRE EL MENSAJE DE INMEDIATO.'
          : 'Respuesta enviada: Se le indicó a tu familiar que puede estar tranquilo.',
      data: { consultation: updated },
    });
  }

  /**
   * POST /api/v1/senior/emergency-report
   * Botón de Emergencia "¿Ya diste tu clave o hiciste un pago?":
   * Genera expediente URGENT inmediato en C.I.C.P.C y devuelve línea directa del banco afectado
   */
  static async submitEmergencyReport(rc: RequestContext): Promise<Response> {
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'senior_emergency',
      identifier: `ip:${rc.clientIp}`,
      maxRequests: 10,
      windowSeconds: 60,
      friendlyMessage: 'Tu reporte de emergencia ya está siendo procesado.',
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        { success: false, error: { code: 'INVALID_JSON', message: 'Datos de emergencia inválidos.' } },
        400
      );
    }

    const bankSlug = typeof body.bank_slug === 'string' ? body.bank_slug.trim() : 'banesco';
    const rawImpact = typeof body.incident_impact === 'string' ? body.incident_impact : 'CREDENTIALS_EXPOSED';
    const impact: CicpcIncidentImpact =
      rawImpact === 'FINANCIAL_LOSS' ? 'FINANCIAL_LOSS' : 'CREDENTIALS_EXPOSED';
    const reporterContact =
      typeof body.reporter_contact === 'string' ? body.reporter_contact.trim() : '';
    const suspectInfo =
      typeof body.suspect_info === 'string' ? body.suspect_info.trim() : '';
    const providedScanId = typeof body.scan_id === 'string' ? body.scan_id.trim() : '';

    const seniorRepo = new SeniorRepository(rc.env.DB);
    const scanRepo = new ScanRepository(rc.env.DB);
    const cicpcRepo = new CicpcRepository(rc.env.DB);

    const bankEntry = await seniorRepo.getDirectoryEntryBySlug(bankSlug);
    const bankName = bankEntry ? bankEntry.entity_name : 'Entidad Bancaria Nacional';
    const emergencyPhone = bankEntry ? bankEntry.emergency_phone : '0800-2427224';

    let finalScanId = '';
    let targetUrl = 'https://emergencia-adulto-mayor.detector360.ejemplo/reporte-urgente';
    let targetDomain = 'emergencia-adulto-mayor.local';

    if (providedScanId) {
      const existingScan = await scanRepo.getScanReportById(providedScanId);
      if (existingScan) {
        finalScanId = existingScan.scan_id;
        targetUrl = existingScan.target_url;
        targetDomain = existingScan.target_domain;
      }
    }

    if (!finalScanId) {
      finalScanId = CryptoService.generateUlid('scn');
      const nowIso = new Date().toISOString();
      const sha = await CryptoService.sha256Hex(`${finalScanId}|EMERGENCY|${bankName}|${nowIso}`);
      await scanRepo.createScanWithFindings({
        report: {
          scan_id: finalScanId,
          target_url: targetUrl,
          final_url: targetUrl,
          target_domain: targetDomain,
          scanned_at: nowIso,
          duration_ms: 15,
          risk_score: 98,
          risk_level: 'CRITICAL',
          citizen_verdict: {
            title: 'EMERGENCIA CIUDADANA: Exposición de Clave o Pago Fraudulento',
            summary: `Activación del protocolo de contención inmediata Adulto Mayor para ${bankName}.`,
            action_steps: [
              `Llamar de inmediato al ${emergencyPhone} para bloquear tarjetas y banca en línea.`,
              'Conservar mensajes y capturas sin borrar evidencia para el C.I.C.P.C.',
            ],
          },
          transport_audit: {
            protocol: 'https',
            is_https: true,
            http_status_code: 200,
            redirect_count: 0,
            security_headers: {
              strict_transport_security: false,
              content_security_policy: false,
              x_frame_options: false,
            },
          },
          findings: [],
          source_preview: [
            {
              line: 1,
              content: `Emergencia reportada: ${suspectInfo || 'Exposición de credenciales / pago bajo engaño'}`,
              has_finding: true,
            },
          ],
          integrity_sha256: sha,
        },
        userId: rc.user ? rc.user.id : null,
        finalUrl: targetUrl,
        httpStatusCode: 200,
        r2SnapshotKey: null,
      });
    }

    const cicpcCase = await cicpcRepo.registerNotificationOrComplaint({
      scanId: finalScanId,
      reportedByUserId: rc.user ? rc.user.id : null,
      sourceType: 'CITIZEN_COMPLAINT',
      targetUrl,
      targetDomain,
      riskScore: 98,
      riskLevel: 'CRITICAL',
      channelReceived: 'whatsapp',
      impersonatedEntity: bankName,
      suspectContact: suspectInfo.slice(0, 120),
      incidentImpact: impact,
      citizenStatement: `[PROTOCOLO EMERGENCIA ADULTO MAYOR] El ciudadano reporta haber entregado clave o realizado transferencia. Banco afectado: ${bankName}. Detalle: ${suspectInfo || 'Solicitud de bloqueo y rastreo urgente.'}`,
      reporterContact,
    });

    return jsonResponse(
      {
        success: true,
        message: 'Expediente prioritario enviado al C.I.C.P.C. Llama ahora mismo al número oficial de bloqueo.',
        data: {
          case_id: cicpcCase.id,
          case_number: cicpcCase.case_number,
          priority: cicpcCase.priority,
          bank_name: bankName,
          emergency_phone: emergencyPhone,
          cicpc_phone: '0800-2427224',
        },
      },
      201
    );
  }
}
