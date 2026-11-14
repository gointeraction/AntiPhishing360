import type {
  RiskLevel,
  ScanFindingDTO,
  SourcePreviewLine,
  TransportAuditResult,
} from '../types.ts';
import { CryptoService } from './crypto.service.ts';

export interface ScoringEvaluation {
  riskScore: number;
  riskLevel: RiskLevel;
  allFindings: ScanFindingDTO[];
  citizenVerdict: {
    title: string;
    summary: string;
    action_steps: string[];
  };
  sourcePreview: SourcePreviewLine[];
}

const SEVERITY_POINTS: Record<string, number> = {
  CRITICAL: 42,
  HIGH: 25,
  MEDIUM: 14,
  LOW: 6,
};

export class ScoringService {
  static evaluate(
    transport: TransportAuditResult,
    domFindings: ScanFindingDTO[],
    jsFindings: ScanFindingDTO[]
  ): ScoringEvaluation {
    const allFindings: ScanFindingDTO[] = [];

    // Transport-level findings
    if (!transport.isHttps) {
      allFindings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'MISSING_HTTPS_ENCRYPTION',
        category: 'TRANSPORT',
        severity: domFindings.length > 0 ? 'CRITICAL' : 'HIGH',
        line_number: 1,
        column_number: 1,
        dom_selector: 'document:protocol(http)',
        citizen_explanation:
          'Esta página NO tiene candado de cifrado (usa http:// en vez de https://). Cualquier persona conectada a la misma red Wi-Fi o en el camino puede leer lo que envíes.',
        technical_detail:
          'Transporte HTTP plano sin cifrado TLS; ausencia total de confidencialidad e integridad de canal.',
        code_snippet: `GET ${transport.finalUrl} (Protocolo sin cifrar HTTP/1.1)`,
      });
    } else {
      const missingHeaders: string[] = [];
      if (!transport.securityHeaders.strict_transport_security) missingHeaders.push('HSTS');
      if (!transport.securityHeaders.content_security_policy) missingHeaders.push('CSP');
      if (!transport.securityHeaders.x_frame_options) missingHeaders.push('X-Frame-Options');

      if (missingHeaders.length === 3) {
        allFindings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'MISSING_DEFENSIVE_SECURITY_HEADERS',
          category: 'TRANSPORT',
          severity: 'MEDIUM',
          line_number: 1,
          column_number: 1,
          dom_selector: 'document:headers',
          citizen_explanation:
            'Aunque la página tiene candado básico, le faltan escudos adicionales que usan los bancos y comercios serios para evitar suplantaciones.',
          technical_detail: `Ausencia de cabeceras defensivas HTTP recomendadas: ${missingHeaders.join(', ')}.`,
          code_snippet: `HTTP ${transport.httpStatusCode} - Sin cabeceras HSTS / CSP / X-Frame-Options`,
        });
      }
    }

    // suspicious TLD heuristic bonus check (.xyz, .top, .click, .zip with banking/package keywords)
    if (/\.(xyz|top|click|buzz|rest|gq|tk)$/i.test(transport.targetDomain)) {
      allFindings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'HIGH_RISK_DISPOSABLE_TLD',
        category: 'TRANSPORT',
        severity: 'MEDIUM',
        line_number: 1,
        column_number: 1,
        dom_selector: 'document:domain',
        citizen_explanation: `La dirección termina en una extensión económica (${transport.targetDomain.split('.').pop()}) muy usada por estafadores para crear páginas descartables.`,
        technical_detail: `Dominio registrado bajo TLD con alta incidencia estadística de campañas efímeras de phishing (${transport.targetDomain}).`,
        code_snippet: `Host: ${transport.targetDomain}`,
      });
    }

    allFindings.push(...domFindings, ...jsFindings);

    // Score calculation
    let rawScore = 0;
    for (const f of allFindings) {
      rawScore += SEVERITY_POINTS[f.severity] ?? 8;
    }

    if (transport.redirectCount >= 3) {
      rawScore += 10;
    }

    // Clamp to 0..99 (or 5 for completely clean HTTPS sites so circular gauge looks alive)
    let riskScore = Math.min(99, rawScore);
    if (allFindings.length === 0 && transport.isHttps) {
      riskScore = 4;
    }

    let riskLevel: RiskLevel = 'SAFE';
    if (riskScore >= 70) {
      riskLevel = 'CRITICAL';
    } else if (riskScore >= 30) {
      riskLevel = 'WARNING';
    }

    const citizenVerdict = this.buildCitizenVerdict(riskLevel, allFindings, transport);
    const sourcePreview = this.buildSourcePreview(transport.htmlContent, allFindings);

    return {
      riskScore,
      riskLevel,
      allFindings,
      citizenVerdict,
      sourcePreview,
    };
  }

  private static buildCitizenVerdict(
    riskLevel: RiskLevel,
    findings: ScanFindingDTO[],
    transport: TransportAuditResult
  ): { title: string; summary: string; action_steps: string[] } {
    const hasCardTrap = findings.some((f) => f.rule_code === 'UNENCRYPTED_PAYMENT_CARD_INPUT');
    const hasCrossDomain = findings.some((f) => f.rule_code === 'CROSS_DOMAIN_FORM_ACTION');
    const hasKeylogger = findings.some(
      (f) => f.rule_code === 'SUSPICIOUS_KEYLOGGER_EXFILTRATION'
    );

    if (riskLevel === 'CRITICAL') {
      if (hasCardTrap) {
        return {
          title: 'ALTO: No escribas tus datos aquí. Esta página intenta robar tu tarjeta',
          summary:
            'Detectamos que esta página no protege tu información con cifrado y desvía los datos de pago hacia terceros desconocidos.',
          action_steps: [
            '1. Cierra esa página inmediatamente y no ingreses números de tarjeta ni códigos CVV.',
            '2. Si te llegó por SMS o WhatsApp sobre un supuesto paquete o premio, bloquea al remitente.',
            '3. Comparte esta alerta con tus familiares para evitar que caigan en la trampa.',
          ],
        };
      }

      if (hasKeylogger || hasCrossDomain) {
        return {
          title: 'ALTO: Peligro Crítico. Esta página es una trampa para robar tus claves',
          summary:
            'Nuestros Rayos X descubrieron código oculto que envía tus contraseñas a un servidor externo pirata sin tu permiso.',
          action_steps: [
            '1. Cierra la pestaña de inmediato; no escribas tu usuario, cédula ni contraseña.',
            '2. Si necesitas entrar a tu banco, hazlo solo desde su aplicación oficial o escribiendo tú mismo su dirección.',
            '3. Si ya llegaste a escribir algún dato en esa página, cambia tu clave de inmediato.',
          ],
        };
      }

      return {
        title: 'ALTO: No escribas tus datos aquí. Esta página no protege tu información',
        summary:
          'La página solicita información delicada sin candado de seguridad, dejando tus datos expuestos como una postal abierta.',
        action_steps: [
          '1. No llenes ningún formulario ni entregues contraseñas o documentos en este enlace.',
          '2. Desconfía de mensajes urgentes sobre bonos, bloqueos de cuenta o premios.',
          '3. Borra el mensaje donde recibiste este enlace para no abrirlo por error.',
        ],
      };
    }

    if (riskLevel === 'WARNING') {
      return {
        title: 'PRECAUCIÓN: Faltan medidas de seguridad importantes en este sitio',
        summary: `Revisamos ${transport.targetDomain}: no encontramos robo directo de claves, pero le faltan protecciones modernas recomendadas.`,
        action_steps: [
          '1. Evita ingresar datos de tarjetas de crédito o contraseñas importantes en esta página.',
          '2. Verifica que el nombre de la dirección web esté bien escrito letra por letra.',
          '3. Si vas a realizar una compra, prefiere comercios verificados con todos sus escudos activos.',
        ],
      };
    }

    return {
      title: 'SITIO SEGURO Y CIFRADO: No detectamos trampas ocultas en su código',
      summary: `La conexión hacia ${transport.targetDomain} cuenta con candado HTTPS activo y sus formularios no muestran desvíos sospechosos.`,
      action_steps: [
        '1. La conexión técnica es segura y cifra tus datos correctamente.',
        '2. Aun así, confirma siempre que el nombre del sitio corresponda a la empresa oficial que buscas.',
        '3. Nunca compartas códigos temporales recibidos por SMS con desconocidos por teléfono.',
      ],
    };
  }

  private static buildSourcePreview(
    html: string,
    findings: ScanFindingDTO[]
  ): SourcePreviewLine[] {
    const rawLines = (html || '').split(/\r?\n/);
    if (rawLines.length === 0 || (rawLines.length === 1 && !rawLines[0])) {
      return [{ line: 1, content: '<!-- Documento sin cuerpo HTML visible -->', has_finding: false }];
    }

    const flaggedLines = new Set<number>();
    for (const f of findings) {
      if (f.line_number >= 1 && f.line_number <= rawLines.length && f.category !== 'TRANSPORT') {
        flaggedLines.add(f.line_number);
      }
    }

    // If there are code findings, collect context windows (+/- 2 lines around each finding)
    if (flaggedLines.size > 0) {
      const selectedIndices = new Set<number>();
      for (const ln of flaggedLines) {
        for (let offset = -2; offset <= 2; offset++) {
          const candidate = ln + offset;
          if (candidate >= 1 && candidate <= rawLines.length) {
            selectedIndices.add(candidate);
          }
        }
      }

      const sorted = Array.from(selectedIndices).sort((a, b) => a - b).slice(0, 35);
      return sorted.map((lineNum) => ({
        line: lineNum,
        content: rawLines[lineNum - 1].slice(0, 300),
        has_finding: flaggedLines.has(lineNum),
      }));
    }

    // Otherwise show first 16 lines of clean source
    return rawLines.slice(0, 16).map((content, idx) => ({
      line: idx + 1,
      content: content.slice(0, 300),
      has_finding: false,
    }));
  }
}
