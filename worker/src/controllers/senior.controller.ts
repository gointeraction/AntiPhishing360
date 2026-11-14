import type { CicpcIncidentImpact, Env, RequestContext, RiskLevel, ScanReportDTO } from '../types.ts';
import { jsonResponse } from '../middlewares/security.middleware.ts';
import { getJwtSecret, parseCookies } from '../middlewares/auth.middleware.ts';
import { RateLimitMiddleware } from '../middlewares/rateLimit.middleware.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { SeniorProtectionService } from '../services/senior-protection.service.ts';
import {
  type GuardianEventType,
  SeniorRepository,
} from '../repositories/senior.repository.ts';
import { ScanRepository } from '../repositories/scan.repository.ts';
import { CicpcRepository } from '../repositories/cicpc.repository.ts';

function getFamilyJwtSecret(env: Env): string {
  return `${getJwtSecret(env)}::FAMILY_GUARDIAN_PORTAL_V1`;
}

function buildFamilySessionCookie(request: Request, token: string): string[] {
  const isHttps = new URL(request.url).protocol === 'https:';
  const name = isHttps ? '__Host-d360_family_session' : 'd360_family_session';
  const sec = isHttps ? '; Secure' : '';
  return [`${name}=${encodeURIComponent(token)}; HttpOnly${sec}; SameSite=Strict; Path=/; Max-Age=43200`];
}

function buildClearFamilySessionCookie(request: Request): string[] {
  const isHttps = new URL(request.url).protocol === 'https:';
  const name = isHttps ? '__Host-d360_family_session' : 'd360_family_session';
  const sec = isHttps ? '; Secure' : '';
  return [`${name}=; HttpOnly${sec}; SameSite=Strict; Path=/; Max-Age=0`];
}

async function resolveFamilySession(
  request: Request,
  env: Env
): Promise<{ family_code: string; guardian_name: string } | null> {
  const cookies = parseCookies(request.headers.get('Cookie'));
  const token = cookies['__Host-d360_family_session'] || cookies['d360_family_session'] || '';
  if (!token) return null;

  const payload = await CryptoService.verifyJwt<{
    sub: string;
    family_code: string;
    guardian_name: string;
    scope: string;
  }>(token, getFamilyJwtSecret(env));

  if (!payload || payload.scope !== 'FAMILY_GUARDIAN' || !payload.family_code) {
    return null;
  }
  return {
    family_code: payload.family_code,
    guardian_name: payload.guardian_name,
  };
}

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
    const familyCode = typeof body.family_code === 'string' ? body.family_code.trim() : '';
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

    if (familyCode) {
      await repo
        .recordFamilyActivityEvent({
          familyCode,
          consultationToken: consultation.token,
          scanId,
          eventType: alertMode,
          targetUrl,
          contentSummary:
            messageExcerpt || `Solicitud de apoyo familiar (${alertMode}) sobre ${targetUrl}`,
          riskScore,
          riskLevel,
          familyStatus: 'PENDING',
        })
        .catch(() => {});
    }

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

    const familyCode = typeof body.family_code === 'string' ? body.family_code.trim() : '';
    if (familyCode) {
      await seniorRepo
        .recordFamilyActivityEvent({
          familyCode,
          scanId: finalScanId,
          eventType: 'EMERGENCY_TRIGGERED',
          targetUrl,
          contentSummary: `EMERGENCIA ACTIVADA (${bankName}): El adulto mayor reportó exposición de clave o pago (${cicpcCase.case_number}). ¡Llamar de inmediato!`,
          riskScore: 98,
          riskLevel: 'CRITICAL',
          familyStatus: 'PENDING',
        })
        .catch(() => {});
    }

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

  // ==========================================================================
  // PORTAL DEDICADO DEL FAMILIAR (/familiar): ACCESO Y MONITOREO DEL ABUELO
  // ==========================================================================

  /**
   * POST /api/v1/senior/family/register
   * Crea un nuevo Código de Vínculo Familiar y autentica al familiar
   */
  static async registerFamilyLink(rc: RequestContext): Promise<Response> {
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'family_reg',
      identifier: `ip:${rc.clientIp}`,
      maxRequests: 10,
      windowSeconds: 60,
      friendlyMessage: 'Espera unos segundos antes de registrar otro vínculo familiar.',
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        { success: false, error: { code: 'INVALID_JSON', message: 'Datos inválidos.' } },
        400
      );
    }

    const seniorName = typeof body.senior_name === 'string' ? body.senior_name.trim() : '';
    const seniorPhone = typeof body.senior_phone === 'string' ? body.senior_phone.trim() : '';
    const guardianName = typeof body.guardian_name === 'string' ? body.guardian_name.trim() : '';
    const guardianPhone = typeof body.guardian_phone === 'string' ? body.guardian_phone.trim() : '';
    const accessKey = typeof body.access_key === 'string' ? body.access_key.trim() : '';

    if (seniorName.length < 2 || guardianName.length < 2) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'MISSING_NAMES',
            message: 'Indica el nombre de la persona mayor y el nombre del familiar responsable.',
          },
        },
        400
      );
    }

    if (accessKey.length < 4) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'WEAK_ACCESS_KEY',
            message: 'Define una clave o PIN familiar de al menos 4 caracteres.',
          },
        },
        400
      );
    }

    const pinHash = await CryptoService.hashPassword(accessKey);
    const repo = new SeniorRepository(rc.env.DB);
    const link = await repo.createFamilyLink({
      seniorName,
      seniorPhone,
      guardianName,
      guardianPhone,
      pinHash,
    });

    await repo.recordFamilyActivityEvent({
      familyCode: link.family_code,
      eventType: 'URL_SCAN',
      targetUrl: 'https://detector360.app',
      contentSummary: `Vínculo familiar creado exitosamente por ${link.guardian_name} para cuidar a ${link.senior_name}.`,
      riskScore: 0,
      riskLevel: 'SAFE',
      familyStatus: 'INFO',
    });

    const jwt = await CryptoService.signJwt(
      {
        sub: link.id,
        family_code: link.family_code,
        guardian_name: link.guardian_name,
        scope: 'FAMILY_GUARDIAN',
      },
      getFamilyJwtSecret(rc.env),
      43200
    );

    const origin = new URL(rc.request.url).origin;
    const pairingUrl = `${origin}/?vincular=${encodeURIComponent(link.family_code)}`;

    return jsonResponse(
      {
        success: true,
        message: 'Vínculo familiar creado. Comparte el enlace de activación con el teléfono de tu familiar mayor.',
        data: {
          family_code: link.family_code,
          senior_name: link.senior_name,
          guardian_name: link.guardian_name,
          pairing_url: pairingUrl,
        },
      },
      201,
      { 'Set-Cookie': buildFamilySessionCookie(rc.request, jwt) }
    );
  }

  /**
   * POST /api/v1/senior/family/login
   * Autenticación del familiar con Código Familiar + Clave/PIN
   */
  static async loginFamilyPortal(rc: RequestContext): Promise<Response> {
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'family_login',
      identifier: `ip:${rc.clientIp}`,
      maxRequests: 12,
      windowSeconds: 60,
      friendlyMessage: 'Demasiados intentos seguidos. Espera un minuto.',
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

    const familyCode =
      typeof body.family_code === 'string' ? body.family_code.trim().toUpperCase() : '';
    const accessKey = typeof body.access_key === 'string' ? body.access_key.trim() : '';

    if (!familyCode || !accessKey) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'MISSING_CREDENTIALS',
            message: 'Ingresa el Código de Vínculo Familiar y tu Clave de Acceso.',
          },
        },
        400
      );
    }

    const repo = new SeniorRepository(rc.env.DB);
    const link = await repo.getFamilyLinkByCode(familyCode);
    if (!link) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Código familiar o clave incorrectos.',
          },
        },
        401
      );
    }

    const valid = await CryptoService.verifyPassword(accessKey, link.pin_hash);
    if (!valid) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Código familiar o clave incorrectos.',
          },
        },
        401
      );
    }

    const jwt = await CryptoService.signJwt(
      {
        sub: link.id,
        family_code: link.family_code,
        guardian_name: link.guardian_name,
        scope: 'FAMILY_GUARDIAN',
      },
      getFamilyJwtSecret(rc.env),
      43200
    );

    return jsonResponse(
      {
        success: true,
        data: {
          family_code: link.family_code,
          senior_name: link.senior_name,
          guardian_name: link.guardian_name,
        },
      },
      200,
      { 'Set-Cookie': buildFamilySessionCookie(rc.request, jwt) }
    );
  }

  /**
   * POST /api/v1/senior/family/logout
   */
  static async logoutFamilyPortal(rc: RequestContext): Promise<Response> {
    return jsonResponse(
      { success: true, message: 'Sesión familiar cerrada correctamente.' },
      200,
      { 'Set-Cookie': buildClearFamilySessionCookie(rc.request) }
    );
  }

  /**
   * GET /api/v1/senior/family/dashboard
   * Sala de monitoreo en tiempo real de cualquier novedad con la persona mayor
   */
  static async getFamilyDashboard(rc: RequestContext): Promise<Response> {
    const session = await resolveFamilySession(rc.request, rc.env);
    if (!session) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'FAMILY_UNAUTHORIZED',
            message: 'Ingresa con tu Código de Vínculo Familiar y Clave de Acceso.',
          },
        },
        401
      );
    }

    const repo = new SeniorRepository(rc.env.DB);
    const link = await repo.getFamilyLinkByCode(session.family_code);
    if (!link) {
      return jsonResponse(
        { success: false, error: { code: 'LINK_NOT_FOUND', message: 'Vínculo no encontrado.' } },
        404
      );
    }

    const url = new URL(rc.request.url);
    const filter = url.searchParams.get('filter') || 'ALL';
    const [allEvents, filteredEvents] = await Promise.all([
      repo.listFamilyActivityFeed({ familyCode: link.family_code, filter: 'ALL', limit: 100 }),
      repo.listFamilyActivityFeed({ familyCode: link.family_code, filter, limit: 80 }),
    ]);

    const pendingCount = allEvents.filter((e) => e.family_status === 'PENDING').length;
    const criticalBlocked = allEvents.filter((e) => e.risk_level === 'CRITICAL').length;
    const activeEmergency = allEvents.some(
      (e) => e.event_type === 'EMERGENCY_TRIGGERED' && e.family_status === 'PENDING'
    );

    const overallStatus = activeEmergency
      ? 'EMERGENCY'
      : pendingCount > 0
      ? 'NEEDS_ATTENTION'
      : 'CALM_PROTECTED';

    const origin = url.origin;

    return jsonResponse({
      success: true,
      data: {
        family_profile: {
          family_code: link.family_code,
          senior_name: link.senior_name,
          senior_phone: link.senior_phone,
          guardian_name: link.guardian_name,
          guardian_phone: link.guardian_phone,
          latest_family_broadcast: link.latest_family_broadcast,
          broadcast_updated_at: link.broadcast_updated_at,
          last_senior_activity_at: link.last_senior_activity_at,
          pairing_url: `${origin}/?vincular=${encodeURIComponent(link.family_code)}`,
        },
        kpis: {
          overall_status: overallStatus,
          total_events: allEvents.length,
          pending_consultations: pendingCount,
          critical_threats_blocked: criticalBlocked,
        },
        events: filteredEvents,
      },
    });
  }

  /**
   * POST /api/v1/senior/family/events
   * Registra automáticamente en el feed del familiar cualquier revisión hecha por el adulto mayor
   */
  static async reportSeniorDeviceEvent(rc: RequestContext): Promise<Response> {
    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        { success: false, error: { code: 'INVALID_JSON', message: 'Evento inválido.' } },
        400
      );
    }

    const familyCode =
      typeof body.family_code === 'string' ? body.family_code.trim().toUpperCase() : '';
    if (!familyCode) {
      return jsonResponse(
        { success: false, error: { code: 'MISSING_FAMILY_CODE', message: 'Sin código familiar.' } },
        400
      );
    }

    const allowedTypes = new Set<GuardianEventType>([
      'URL_SCAN',
      'MESSAGE_SCAN',
      'QR_SCAN',
      'ASK_GUARDIAN',
      'AUTO_CRITICAL_ALERT',
      'EMERGENCY_TRIGGERED',
    ]);
    const rawType = typeof body.event_type === 'string' ? (body.event_type as GuardianEventType) : 'URL_SCAN';
    const eventType: GuardianEventType = allowedTypes.has(rawType) ? rawType : 'URL_SCAN';
    const targetUrl = typeof body.target_url === 'string' ? body.target_url.trim() : '';
    const contentSummary =
      typeof body.content_summary === 'string' ? body.content_summary.trim() : '';
    const scanId = typeof body.scan_id === 'string' ? body.scan_id.trim() : null;
    const riskScore = typeof body.risk_score === 'number' ? body.risk_score : 0;
    const rawLevel = typeof body.risk_level === 'string' ? body.risk_level : 'SAFE';
    const riskLevel: RiskLevel =
      rawLevel === 'CRITICAL' || rawLevel === 'WARNING' ? rawLevel : 'SAFE';

    const repo = new SeniorRepository(rc.env.DB);
    const created = await repo.recordFamilyActivityEvent({
      familyCode,
      scanId,
      eventType,
      targetUrl,
      contentSummary,
      riskScore,
      riskLevel,
    });

    if (!created) {
      return jsonResponse(
        { success: false, error: { code: 'FAMILY_CODE_NOT_FOUND', message: 'Código no registrado.' } },
        404
      );
    }

    return jsonResponse({ success: true, data: { event: created } }, 201);
  }

  /**
   * PATCH /api/v1/senior/family/events/:event_id
   * El familiar responde o marca como atendida cualquier novedad desde su panel /familiar
   */
  static async updateFamilyEventDecision(rc: RequestContext): Promise<Response> {
    const session = await resolveFamilySession(rc.request, rc.env);
    if (!session) {
      return jsonResponse(
        { success: false, error: { code: 'FAMILY_UNAUTHORIZED', message: 'No autorizado.' } },
        401
      );
    }

    const eventId = rc.params.event_id || '';
    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        { success: false, error: { code: 'INVALID_JSON', message: 'Datos inválidos.' } },
        400
      );
    }

    const rawStatus =
      typeof body.status === 'string'
        ? body.status.toUpperCase()
        : typeof body.decision === 'string'
        ? body.decision.toUpperCase()
        : '';
    if (
      rawStatus !== 'SAFE_APPROVED' &&
      rawStatus !== 'DANGER_DELETE' &&
      rawStatus !== 'RESOLVED_BY_CALL'
    ) {
      return jsonResponse(
        { success: false, error: { code: 'INVALID_STATUS', message: 'Estado inválido.' } },
        400
      );
    }

    const note = typeof body.note === 'string' ? body.note.trim() : '';
    const repo = new SeniorRepository(rc.env.DB);
    const updated = await repo.updateFamilyEventDecision({
      familyCode: session.family_code,
      eventId,
      status: rawStatus,
      note,
    });

    if (!updated) {
      return jsonResponse(
        { success: false, error: { code: 'EVENT_NOT_FOUND', message: 'Novedad no encontrada.' } },
        404
      );
    }

    return jsonResponse({
      success: true,
      message: 'Indicación guardada y sincronizada con el teléfono de tu familiar mayor.',
      data: { event: updated },
    });
  }

  /**
   * POST /api/v1/senior/family/broadcast
   * Envía un mensaje tranquilizador directo a la pantalla del abuelo
   */
  static async sendFamilyBroadcast(rc: RequestContext): Promise<Response> {
    const session = await resolveFamilySession(rc.request, rc.env);
    if (!session) {
      return jsonResponse(
        { success: false, error: { code: 'FAMILY_UNAUTHORIZED', message: 'No autorizado.' } },
        401
      );
    }

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        { success: false, error: { code: 'INVALID_JSON', message: 'Mensaje inválido.' } },
        400
      );
    }

    const message = typeof body.message === 'string' ? body.message.trim() : '';
    if (message.length < 3) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'EMPTY_MESSAGE', message: 'Escribe un mensaje breve para tu familiar.' },
        },
        400
      );
    }

    const repo = new SeniorRepository(rc.env.DB);
    const updated = await repo.updateFamilyBroadcast({
      familyCode: session.family_code,
      message,
    });

    return jsonResponse({
      success: true,
      message: 'Mensaje enviado a la pantalla de tu familiar mayor.',
      data: {
        latest_family_broadcast: updated?.latest_family_broadcast || message,
        broadcast_updated_at: updated?.broadcast_updated_at || new Date().toISOString(),
      },
    });
  }

  /**
   * GET /api/v1/senior/family/senior-sync/:family_code
   * Permite que el teléfono del abuelo reciba avisos y respuestas de su familiar en tiempo real
   */
  static async getSeniorLiveSync(rc: RequestContext): Promise<Response> {
    const code = (rc.params.family_code || '').trim().toUpperCase();
    if (!code) {
      return jsonResponse(
        { success: false, error: { code: 'MISSING_CODE', message: 'Código faltante.' } },
        400
      );
    }

    const repo = new SeniorRepository(rc.env.DB);
    const link = await repo.getFamilyLinkByCode(code);
    if (!link) {
      return jsonResponse(
        { success: false, error: { code: 'NOT_FOUND', message: 'Vínculo no encontrado.' } },
        404
      );
    }

    const recentEvents = await repo.listFamilyActivityFeed({
      familyCode: code,
      filter: 'ALL',
      limit: 5,
    });
    const latestAnswered = recentEvents.find(
      (e) => e.family_status === 'DANGER_DELETE' || e.family_status === 'SAFE_APPROVED'
    );

    return jsonResponse({
      success: true,
      data: {
        family_code: link.family_code,
        senior_name: link.senior_name,
        guardian_name: link.guardian_name,
        guardian_phone: link.guardian_phone,
        latest_family_broadcast: link.latest_family_broadcast,
        broadcast_updated_at: link.broadcast_updated_at,
        latest_answered_event: latestAnswered || null,
      },
    });
  }
}
