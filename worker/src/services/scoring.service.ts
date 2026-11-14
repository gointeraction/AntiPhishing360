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
  CRITICAL: 46,
  HIGH: 26,
  MEDIUM: 14,
  LOW: 6,
};

const DECISIVE_CRITICAL_FLOOR: Record<string, number> = {
  TELEGRAM_OR_WEBHOOK_EXFILTRATION: 94,
  VISUAL_BANK_IMAGE_IMPERSONATION: 90,
  SUSPICIOUS_KEYLOGGER_EXFILTRATION: 88,
  FORENSIC_OPEN_PHISHING_KIT_DIRECTORY: 88,
  SPA_HIDDEN_CREDENTIAL_HARVESTER: 85,
  BANK_BRAND_CONTENT_IMPERSONATION: 84,
  FREE_HOSTING_CREDENTIAL_PHISHING: 82,
  CTI_IDN_HOMOGLYPH_ATTACK: 85,
  CTI_LEET_HOMOGLYPH_BRAND_SPOOF: 84,
  CTI_DNSTWIST_TYPOSQUATTING: 82,
  CTI_DIRECT_IPV4_PHISHING_HOST: 82,
};

export class ScoringService {
  static evaluate(
    transport: TransportAuditResult,
    domFindings: ScanFindingDTO[],
    jsFindings: ScanFindingDTO[],
    urlCtiFindings: ScanFindingDTO[] = []
  ): ScoringEvaluation {
    const allFindings: ScanFindingDTO[] = [...urlCtiFindings];

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

    // suspicious TLD heuristic bonus check (.xyz, .top, .click, .online, .site, .icu, .cfd, .sbs, etc.)
    if (
      /\.(xyz|top|click|buzz|rest|gq|tk|ml|cf|ga|online|site|icu|cfd|sbs|cyou|vip|fun|pw|su)$/i.test(
        transport.targetDomain
      )
    ) {
      allFindings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'HIGH_RISK_DISPOSABLE_TLD',
        category: 'TRANSPORT',
        severity: 'MEDIUM',
        line_number: 1,
        column_number: 1,
        dom_selector: 'document:domain',
        citizen_explanation: `La dirección termina en una extensión económica (.${transport.targetDomain.split('.').pop()}) muy usada por estafadores para crear páginas descartables.`,
        technical_detail: `Dominio registrado bajo TLD con alta incidencia estadística de campañas efímeras de phishing (${transport.targetDomain}).`,
        code_snippet: `Host: ${transport.targetDomain}`,
      });
    }

    allFindings.push(...domFindings, ...jsFindings);

    // Score calculation with decisive floor for confirmed phishing signatures
    let rawScore = 0;
    let decisiveFloor = 0;
    for (const f of allFindings) {
      rawScore += SEVERITY_POINTS[f.severity] ?? 8;
      if (DECISIVE_CRITICAL_FLOOR[f.rule_code]) {
        decisiveFloor = Math.max(decisiveFloor, DECISIVE_CRITICAL_FLOOR[f.rule_code]);
      } else if (f.rule_code === 'CROSS_DOMAIN_FORM_ACTION' && f.severity === 'CRITICAL') {
        decisiveFloor = Math.max(decisiveFloor, 80);
      }
    }

    if (transport.redirectCount >= 3) {
      rawScore += 10;
    }

    // Clamp to 0..99 (or 4 for completely clean HTTPS sites so circular gauge looks alive)
    let riskScore = Math.min(99, Math.max(rawScore, decisiveFloor));
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
    const hasVisualBankImpersonation = findings.some((f) =>
      ['VISUAL_BANK_IMAGE_IMPERSONATION', 'BANK_BRAND_CONTENT_IMPERSONATION'].includes(f.rule_code)
    );
    const hasActiveExfiltration = findings.some((f) =>
      [
        'TELEGRAM_OR_WEBHOOK_EXFILTRATION',
        'SPA_HIDDEN_CREDENTIAL_HARVESTER',
        'FREE_HOSTING_CREDENTIAL_PHISHING',
      ].includes(f.rule_code)
    );
    const hasBrandSpoofCti = findings.some((f) =>
      [
        'CTI_DNSTWIST_TYPOSQUATTING',
        'CTI_LEET_HOMOGLYPH_BRAND_SPOOF',
        'CTI_BRAND_COMBOSQUATTING_IMPERSONATION',
        'CTI_IDN_HOMOGLYPH_ATTACK',
        'CTI_DIRECT_IPV4_PHISHING_HOST',
      ].includes(f.rule_code)
    );

    if (riskLevel === 'CRITICAL') {
      if (hasVisualBankImpersonation) {
        const bankFinding = findings.find((f) =>
          ['VISUAL_BANK_IMAGE_IMPERSONATION', 'BANK_BRAND_CONTENT_IMPERSONATION'].includes(
            f.rule_code
          )
        );
        return {
          title: 'ALTO: NO ES PÁGINA OFICIAL — Suplantación de Imágenes e Identidad Bancaria',
          summary:
            bankFinding?.citizen_explanation ||
            `Comparamos los logotipos e imágenes de ${transport.targetDomain} y determinamos que copia la imagen de una entidad bancaria desde una dirección falsa.`,
          action_steps: [
            '1. NO escribas tu usuario, contraseña, cédula, clave especial ni códigos SMS en esta página.',
            '2. Aunque veas el logotipo de tu banco y un candado arriba, el dominio NO pertenece a la institución oficial.',
            '3. Cierra esta ventana y entra únicamente desde la App oficial de tu banco o buscando su portal en nuestro Directorio Verificado.',
          ],
        };
      }

      if (hasActiveExfiltration) {
        return {
          title: 'ALTO: Trampa Activa de Phishing Confirmada (Captura Oculta de Claves)',
          summary:
            'Al verificar la funcionalidad interna del enlace, detectamos formularios falsos o envío directo de credenciales hacia bots de estafadores (Telegram / Discord / servidores piratas).',
          action_steps: [
            '1. Cierra la página de inmediato y bloquea el número o remitente que te envió el enlace.',
            '2. Si ya escribiste tu clave o código bancario, usa el botón rojo de Emergencia arriba para bloquear tus tarjetas.',
            '3. Pulsa "Notificar Caso al C.I.C.P.C" para reportar este enlace activo.',
          ],
        };
      }
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

      if (hasBrandSpoofCti) {
        return {
          title: 'ALTO: Dirección web impostora detectada (Suplantación de Marca / Typosquatting)',
          summary:
            'Nuestro motor predictivo de URLs descubrió que este enlace imita maliciosamente el nombre de una entidad real cambiando letras, usando números parecidos o dominios falsos.',
          action_steps: [
            '1. No abras este enlace ni ingreses usuario, clave o códigos dinámicos.',
            '2. Entra siempre desde la aplicación oficial o escribiendo tú mismo la dirección legítima.',
            '3. Usa el botón "Notificar Caso al C.I.C.P.C" para bloquear esta infraestructura fraudulenta.',
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
      if (hasBrandSpoofCti) {
        return {
          title: 'ALERTA TEMPRANA: Esta dirección web imita el nombre de una institución real',
          summary: `Aunque ${transport.targetDomain} usa cifrado HTTPS, su dirección presenta señales de suplantación o typosquatting respecto a la página oficial.`,
          action_steps: [
            '1. No ingreses contraseñas ni datos bancarios hasta verificar letra por letra la dirección.',
            '2. Compara este enlace con el portal oficial de tu banco o servicio.',
            '3. Ante cualquier duda, repórtalo al C.I.C.P.C desde este reporte.',
          ],
        };
      }

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
