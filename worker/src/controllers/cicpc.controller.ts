import type {
  CicpcCaseStatus,
  CicpcIncidentImpact,
  CicpcPriority,
  CicpcStrategicAction,
  RequestContext,
} from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { CicpcRepository } from '../repositories/cicpc.repository.ts';
import { ScanRepository } from '../repositories/scan.repository.ts';
import { jsonResponse } from '../middlewares/security.middleware.ts';
import { RateLimitMiddleware } from '../middlewares/rateLimit.middleware.ts';
import {
  buildCicpcAuthCookie,
  buildClearCicpcAuthCookie,
  getCicpcJwtSecret,
  resolveCicpcOfficer,
} from '../middlewares/cicpc-auth.middleware.ts';

const VALID_STATUSES = new Set<CicpcCaseStatus>([
  'pending',
  'in_analysis',
  'strategic_action',
  'mitigated',
  'archived',
]);

const VALID_PRIORITIES = new Set<CicpcPriority>(['URGENT', 'HIGH', 'NORMAL']);

const VALID_STRATEGIC_ACTIONS = new Set<CicpcStrategicAction>([
  'NONE',
  'ISP_DNS_BLOCK_REQUEST',
  'REGISTRAR_TAKEDOWN',
  'BANKING_FRAUD_ALERT',
  'TRACE_EXFILTRATION_SERVER',
  'PUBLIC_PREVENTION_BULLETIN',
  'FIELD_INVESTIGATION_OPENED',
]);

function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export class CicpcController {
  // --------------------------------------------------------------------------
  // 1. RECEPCIÓN DE DENUNCIAS Y NOTIFICACIONES CIUDADANAS (PÚBLICO / AUTENTICADO)
  // --------------------------------------------------------------------------
  static async submitCitizenCase(rc: RequestContext): Promise<Response> {
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'cicpc_citizen_report',
      identifier: rc.user ? `usr:${rc.user.id}` : `ip:${rc.clientIp}`,
      maxRequests: 15,
      windowSeconds: 600,
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_JSON', message: 'Formato de notificación inválido.' },
        },
        400
      );
    }

    const scanId = typeof body.scan_id === 'string' ? body.scan_id.trim() : '';
    if (!scanId.startsWith('scn_')) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_SCAN_ID',
            message: 'Debes asociar un análisis forense válido para remitir el caso al C.I.C.P.C.',
          },
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
          error: {
            code: 'SCAN_NOT_FOUND',
            message: 'No se encontró la evidencia forense asociada a este escaneo.',
          },
        },
        404
      );
    }

    const channelReceived =
      typeof body.channel_received === 'string' ? body.channel_received.trim() : 'whatsapp';
    const impersonatedEntity =
      typeof body.impersonated_entity === 'string'
        ? body.impersonated_entity.trim()
        : 'Entidad reportada por ciudadano';
    const suspectContact =
      typeof body.suspect_contact === 'string' ? body.suspect_contact.trim() : '';
    const rawImpact =
      typeof body.incident_impact === 'string' ? body.incident_impact.trim() : 'PREVENTIVE';
    const incidentImpact: CicpcIncidentImpact =
      rawImpact === 'FINANCIAL_LOSS' || rawImpact === 'CREDENTIALS_EXPOSED'
        ? rawImpact
        : 'PREVENTIVE';
    const citizenStatement =
      typeof body.citizen_statement === 'string' ? body.citizen_statement.trim() : '';
    const reporterContact =
      typeof body.reporter_contact === 'string'
        ? body.reporter_contact.trim()
        : rc.user?.email || '';

    const cicpcRepo = new CicpcRepository(rc.env.DB);
    const created = await cicpcRepo.registerNotificationOrComplaint({
      scanId: report.scan_id,
      reportedByUserId: rc.user ? rc.user.id : null,
      sourceType: 'CITIZEN_COMPLAINT',
      targetUrl: report.target_url,
      targetDomain: report.target_domain,
      riskScore: report.risk_score,
      riskLevel: report.risk_level,
      channelReceived,
      impersonatedEntity,
      suspectContact,
      incidentImpact,
      citizenStatement,
      reporterContact,
    });

    return jsonResponse(
      {
        success: true,
        message: `Denuncia y evidencia forense remitidas a la División de Delitos Informáticos bajo el expediente ${created.case_number}.`,
        data: {
          case_id: created.id,
          case_number: created.case_number,
          priority: created.priority,
          status: created.status,
          integrity_sha256: report.integrity_sha256,
        },
      },
      201
    );
  }

  // --------------------------------------------------------------------------
  // 2. ACCESO RESTRINGUIDO CON CLAVES DE SEGURIDAD (FUNCIONARIOS C.I.C.P.C)
  // --------------------------------------------------------------------------
  static async officerLogin(rc: RequestContext): Promise<Response> {
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'cicpc_officer_login',
      identifier: rc.clientIp,
      maxRequests: 8,
      windowSeconds: 300,
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_JSON', message: 'Formato de credenciales inválido.' },
        },
        400
      );
    }

    const badgeId = typeof body.badge_id === 'string' ? body.badge_id.trim().toUpperCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const securityKey = typeof body.security_key === 'string' ? body.security_key.trim() : '';

    if (!badgeId || !password || !securityKey) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'MISSING_SECURITY_FACTORS',
            message:
              'Acceso denegado: Se requieren Credencial Oficial, Contraseña Operativa y Clave Maestra de Seguridad.',
          },
        },
        400
      );
    }

    const cicpcRepo = new CicpcRepository(rc.env.DB);
    const officer = await cicpcRepo.findOfficerByBadge(badgeId);

    if (!officer || officer.is_active !== 1) {
      await cicpcRepo.appendAuditLog({
        officerBadge: badgeId || 'DESCONOCIDO',
        officerName: 'Intento No Autorizado',
        actionCode: 'AUTH_LOGIN_DENIED',
        detail: 'Credencial de funcionario inexistente o inactiva.',
        clientIp: rc.clientIp,
      });

      return jsonResponse(
        {
          success: false,
          error: {
            code: 'ACCESS_DENIED',
            message: 'Acceso restringido denegado: Credenciales o clave de seguridad inválidas.',
          },
        },
        401
      );
    }

    // Factor 2: PBKDF2-HMAC-SHA512 Operational Password
    const validPassword = await CryptoService.verifyPassword(password, officer.password_hash);

    // Factor 3: Institutional Cryptographic Security Key
    const providedKeySha256 = await CryptoService.sha256Hex(securityKey);
    const expectedKeySha256 = rc.env.CICPC_MASTER_KEY
      ? await CryptoService.sha256Hex(rc.env.CICPC_MASTER_KEY)
      : officer.security_key_sha256;
    const validSecurityKey = constantTimeHexEqual(
      providedKeySha256.toLowerCase(),
      expectedKeySha256.toLowerCase()
    );

    if (!validPassword || !validSecurityKey) {
      await cicpcRepo.appendAuditLog({
        officerBadge: officer.badge_id,
        officerName: officer.full_name,
        actionCode: 'AUTH_LOGIN_DENIED',
        detail: !validSecurityKey
          ? 'Fallo de validación en Clave Maestra de Seguridad Institucional.'
          : 'Fallo de validación en Contraseña Operativa.',
        clientIp: rc.clientIp,
      });

      return jsonResponse(
        {
          success: false,
          error: {
            code: 'ACCESS_DENIED',
            message: 'Acceso restringido denegado: Credenciales o clave de seguridad inválidas.',
          },
        },
        401
      );
    }

    await cicpcRepo.touchOfficerLogin(officer.id);
    await cicpcRepo.appendAuditLog({
      officerBadge: officer.badge_id,
      officerName: officer.full_name,
      actionCode: 'AUTH_LOGIN_SUCCESS',
      detail: `Sesión segura iniciada en Centro de Comando (${officer.role}).`,
      clientIp: rc.clientIp,
    });

    const token = await CryptoService.signJwt(
      {
        sub: officer.id,
        badge_id: officer.badge_id,
        full_name: officer.full_name,
        rank_title: officer.rank_title,
        role: officer.role,
        scope: 'CICPC_DIDI_OFFICER',
      },
      getCicpcJwtSecret(rc.env),
      7200
    );

    const cookies = buildCicpcAuthCookie(rc.request, token);

    return jsonResponse(
      {
        success: true,
        message: `Acceso autorizado. Bienvenido, ${officer.full_name}.`,
        data: {
          officer: {
            id: officer.id,
            badge_id: officer.badge_id,
            full_name: officer.full_name,
            rank_title: officer.rank_title,
            role: officer.role,
          },
        },
      },
      200,
      { 'Set-Cookie': cookies }
    );
  }

  static async officerLogout(rc: RequestContext): Promise<Response> {
    const officer = await resolveCicpcOfficer(rc.request, rc.env);
    if (officer) {
      const cicpcRepo = new CicpcRepository(rc.env.DB);
      await cicpcRepo.appendAuditLog({
        officerBadge: officer.badge_id,
        officerName: officer.full_name,
        actionCode: 'AUTH_LOGOUT',
        detail: 'Cierre de sesión de comando ejecutado por el funcionario.',
        clientIp: rc.clientIp,
      });
    }

    const cookies = buildClearCicpcAuthCookie(rc.request);
    return jsonResponse(
      { success: true, message: 'Sesión institucional cerrada de forma segura.' },
      200,
      { 'Set-Cookie': cookies }
    );
  }

  static async officerSession(rc: RequestContext): Promise<Response> {
    const officer = await resolveCicpcOfficer(rc.request, rc.env);
    if (!officer) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'CICPC_UNAUTHORIZED',
            message: 'Acceso restringido. Autentíquese con su credencial y clave de seguridad.',
          },
        },
        401
      );
    }

    return jsonResponse({
      success: true,
      data: { officer },
    });
  }

  // --------------------------------------------------------------------------
  // 3. PANEL DE INTELIGENCIA ESTRATÉGICA, BANDEJA Y DICTAMEN EXPERTO
  // --------------------------------------------------------------------------
  static async getDashboardOverview(rc: RequestContext): Promise<Response> {
    const officer = await resolveCicpcOfficer(rc.request, rc.env);
    if (!officer) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'CICPC_UNAUTHORIZED',
            message: 'Acceso restringido a funcionarios autorizados del C.I.C.P.C.',
          },
        },
        401
      );
    }

    const cicpcRepo = new CicpcRepository(rc.env.DB);
    const [stats, auditLogs] = await Promise.all([
      cicpcRepo.getStrategicDashboardStats(),
      cicpcRepo.listAuditLogs(20),
    ]);

    return jsonResponse({
      success: true,
      data: {
        officer,
        ...stats,
        audit_logs: auditLogs,
      },
    });
  }

  static async listCases(rc: RequestContext): Promise<Response> {
    const officer = await resolveCicpcOfficer(rc.request, rc.env);
    if (!officer) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'CICPC_UNAUTHORIZED',
            message: 'Acceso restringido a funcionarios autorizados del C.I.C.P.C.',
          },
        },
        401
      );
    }

    const url = new URL(rc.request.url);
    const status = url.searchParams.get('status') || 'all';
    const priority = url.searchParams.get('priority') || 'all';
    const channel = url.searchParams.get('channel') || 'all';
    const search = url.searchParams.get('search') || '';

    const cicpcRepo = new CicpcRepository(rc.env.DB);
    const cases = await cicpcRepo.listCases({
      status,
      priority,
      channel,
      search,
      limit: 80,
    });

    return jsonResponse({
      success: true,
      data: {
        total: cases.length,
        cases,
      },
    });
  }

  static async getCaseDetail(rc: RequestContext): Promise<Response> {
    const officer = await resolveCicpcOfficer(rc.request, rc.env);
    if (!officer) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'CICPC_UNAUTHORIZED',
            message: 'Acceso restringido a funcionarios autorizados del C.I.C.P.C.',
          },
        },
        401
      );
    }

    const caseId = rc.params.case_id || '';
    const cicpcRepo = new CicpcRepository(rc.env.DB);
    const detail = await cicpcRepo.getCaseDetailById(caseId);

    if (!detail) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'CASE_NOT_FOUND', message: 'Expediente no encontrado.' },
        },
        404
      );
    }

    return jsonResponse({
      success: true,
      data: detail,
    });
  }

  static async updateCaseDecision(rc: RequestContext): Promise<Response> {
    const officer = await resolveCicpcOfficer(rc.request, rc.env);
    if (!officer) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'CICPC_UNAUTHORIZED',
            message: 'Acceso restringido a funcionarios autorizados del C.I.C.P.C.',
          },
        },
        401
      );
    }

    const caseId = rc.params.case_id || '';
    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_JSON', message: 'Datos de revisión inválidos.' },
        },
        400
      );
    }

    const rawStatus = (typeof body.status === 'string' ? body.status.trim() : 'in_analysis') as CicpcCaseStatus;
    const rawPriority = (typeof body.priority === 'string' ? body.priority.trim() : 'HIGH') as CicpcPriority;
    const rawAction = (
      typeof body.strategic_action_type === 'string' ? body.strategic_action_type.trim() : 'NONE'
    ) as CicpcStrategicAction;
    const expertNotes = typeof body.expert_notes === 'string' ? body.expert_notes.trim() : '';

    if (!VALID_STATUSES.has(rawStatus)) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_STATUS', message: 'Estado operativo inválido.' },
        },
        400
      );
    }

    if (!VALID_PRIORITIES.has(rawPriority)) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_PRIORITY', message: 'Nivel de prioridad inválido.' },
        },
        400
      );
    }

    if (!VALID_STRATEGIC_ACTIONS.has(rawAction)) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'INVALID_ACTION', message: 'Acción estratégica inválida.' },
        },
        400
      );
    }

    const cicpcRepo = new CicpcRepository(rc.env.DB);
    const updated = await cicpcRepo.updateCaseExpertReview({
      caseId,
      status: rawStatus,
      priority: rawPriority,
      strategicActionType: rawAction,
      expertNotes,
      officerBadge: officer.badge_id,
      officerName: officer.full_name,
    });

    if (!updated) {
      return jsonResponse(
        {
          success: false,
          error: { code: 'CASE_NOT_FOUND', message: 'No se encontró el expediente a actualizar.' },
        },
        404
      );
    }

    await cicpcRepo.appendAuditLog({
      officerBadge: officer.badge_id,
      officerName: officer.full_name,
      actionCode: rawAction !== 'NONE' ? 'STRATEGIC_ACTION_EXECUTED' : 'CASE_REVIEWED',
      caseId,
      detail: `Actualizó expediente (${caseId}) → Estado: ${rawStatus} | Prioridad: ${rawPriority} | Acción: ${rawAction}`,
      clientIp: rc.clientIp,
    });

    const refreshed = await cicpcRepo.getCaseDetailById(caseId);

    return jsonResponse({
      success: true,
      message: 'Dictamen experto y acción estratégica registrados en cadena de custodia.',
      data: refreshed,
    });
  }
}
