import {
  CanonicalEvidencePayload,
  CitizenVerdict,
  FindingSeverity,
  RiskLevel,
  ScanFinding,
  SourcePreviewLine,
  TransportAudit
} from '../types/models';
import { CryptoService } from './crypto.service';
import { LineIndexMap } from './dom-parser.service';

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1
};

const RULE_WEIGHTS: Record<string, number> = {
  INSECURE_HTTP_SENSITIVE_FORM: 62,
  INSECURE_HTTP_SENSITIVE_INPUT: 58,
  CROSS_DOMAIN_FORM_ACTION: 55,
  MAILTO_FORM_EXFILTRATION: 55,
  JS_C2_WEBHOOK_EXFILTRATION: 75,
  JS_ASYNC_EXFILTRATION: 58,
  HTTPS_TO_HTTP_DOWNGRADE: 52,
  PLAINTEXT_PASSWORD_FIELD: 45,
  JS_OBFUSCATION_DETECTED: 36,
  UNMASKED_PASSWORD_INPUT: 32,
  INSECURE_HTTP_TRANSPORT: 32,
  PUNYCODE_HOMOGRAPH_DOMAIN: 38,
  RAW_IP_HOST_PHISHING: 35,
  MIXED_CONTENT_INSECURE_SCRIPT: 30,
  SUSPICIOUS_EXTERNAL_SCRIPT_HOST: 32,
  SUSPICIOUS_REDIRECT_CHAIN: 18,
  SUSPICIOUS_HIDDEN_INPUT: 15,
  JS_ANTI_INSPECTION: 16,
  MISSING_SECURITY_HEADERS: 8,
  TRUSTED_EXTERNAL_FORM_PROVIDER: 0
};

const DEFAULT_SEVERITY_WEIGHT: Record<FindingSeverity, number> = {
  CRITICAL: 55,
  HIGH: 32,
  MEDIUM: 16,
  LOW: 5
};

export class ScoringService {
  /**
   * Sorts findings by severity DESC then line_number ASC, computes calibrated 0..100 score,
   * determines SAFE / WARNING / CRITICAL verdict, and builds citizen-friendly verdict copy.
   */
  static evaluateRisk(
    findings: ScanFinding[],
    transport: TransportAudit
  ): {
    sortedFindings: ScanFinding[];
    riskScore: number;
    riskLevel: RiskLevel;
    citizenVerdict: CitizenVerdict;
  } {
    const sortedFindings = [...findings].sort((a, b) => {
      const sevDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (sevDiff !== 0) return sevDiff;
      return a.line_number - b.line_number;
    });

    // Deduplicate identical rule_code weights after 2nd occurrence to prevent runaway inflation on large pages
    const ruleCounts = new Map<string, number>();
    let rawScore = 0;

    for (const f of sortedFindings) {
      const seen = ruleCounts.get(f.rule_code) ?? 0;
      ruleCounts.set(f.rule_code, seen + 1);

      const baseWeight = RULE_WEIGHTS[f.rule_code] ?? DEFAULT_SEVERITY_WEIGHT[f.severity];
      if (seen === 0) {
        rawScore += baseWeight;
      } else if (seen === 1) {
        rawScore += Math.round(baseWeight * 0.35);
      } else {
        rawScore += Math.round(baseWeight * 0.1);
      }
    }

    // Ensure at least CRITICAL threshold (>= 70) whenever any CRITICAL finding exists
    const hasCritical = sortedFindings.some((f) => f.severity === 'CRITICAL');
    if (hasCritical && rawScore < 75) {
      rawScore = 75;
    }

    // Ensure HTTP without sensitive forms at least lands in WARNING (>= 30)
    if (!transport.is_https && rawScore < 32) {
      rawScore = 32;
    }

    const riskScore = Math.max(0, Math.min(100, Math.round(rawScore)));

    let riskLevel: RiskLevel;
    if (riskScore >= 70) {
      riskLevel = 'CRITICAL';
    } else if (riskScore >= 30) {
      riskLevel = 'WARNING';
    } else {
      riskLevel = 'SAFE';
    }

    const citizenVerdict = this.buildCitizenVerdict(riskLevel, sortedFindings, transport);

    return {
      sortedFindings,
      riskScore,
      riskLevel,
      citizenVerdict
    };
  }

  private static buildCitizenVerdict(
    riskLevel: RiskLevel,
    sortedFindings: ScanFinding[],
    transport: TransportAudit
  ): CitizenVerdict {
    if (riskLevel === 'CRITICAL') {
      const topReasons: string[] = [];
      const codes = new Set(sortedFindings.map((f) => f.rule_code));

      if (!transport.is_https || codes.has('INSECURE_HTTP_SENSITIVE_FORM')) {
        topReasons.push('captura contraseñas o datos sensibles sin cifrado HTTPS');
      }
      if (codes.has('CROSS_DOMAIN_FORM_ACTION')) {
        topReasons.push('envía los datos del formulario a un servidor externo ajeno al dominio');
      }
      if (codes.has('JS_ASYNC_EXFILTRATION') || codes.has('JS_C2_WEBHOOK_EXFILTRATION')) {
        topReasons.push('ejecuta scripts ocultos de exfiltración de datos en tiempo real');
      }
      if (codes.has('JS_OBFUSCATION_DETECTED')) {
        topReasons.push('contiene código JavaScript malicioso u ofuscado');
      }

      const reasonSummary =
        topReasons.length > 0
          ? `Se detectó que el sitio ${topReasons.join(' y ')}.`
          : sortedFindings[0]?.citizen_explanation ||
            'Se detectaron patrones estructurales críticos de suplantación o robo de información.';

      return {
        title: 'PELIGRO CRÍTICO: No ingreses tus datos en esta página',
        summary: `${reasonSummary} Cierra el enlace y descarga la evidencia forense si deseas reportarlo.`
      };
    }

    if (riskLevel === 'WARNING') {
      if (!transport.is_https) {
        return {
          title: 'PRECAUCIÓN: Conexión sin cifrado HTTPS',
          summary:
            'El sitio no utiliza cifrado seguro (HTTPS). Aunque no se detectó robo activo de contraseñas, nunca introduzcas información personal ni bancaria aquí.'
        };
      }
      return {
        title: 'PRECAUCIÓN: Se detectaron advertencias técnicas en el sitio',
        summary:
          sortedFindings[0]?.citizen_explanation ||
          'La página presenta configuraciones o scripts que requieren cautela. Verifica cuidadosamente la dirección oficial antes de interactuar.'
      };
    }

    return {
      title: 'SITIO SEGURO: Transporte cifrado y sin rastros de exfiltración',
      summary:
        'La conexión utiliza cifrado HTTPS válido y el análisis estático del código fuente no encontró formularios fraudulentos ni scripts de captura sospechosos.'
    };
  }

  /**
   * Extracts contextual source code lines around detected DOM/JS findings (±2 lines)
   * or the top opening lines of the HTML document when clean, capped to 120 preview lines.
   */
  static buildSourcePreview(
    indexMap: LineIndexMap,
    findings: ScanFinding[],
    contextRadius = 2,
    maxPreviewLines = 120
  ): SourcePreviewLine[] {
    const { lines } = indexMap;
    if (lines.length === 0) {
      return [];
    }

    const findingRulesByLine = new Map<number, string[]>();
    const selectedLineNumbers = new Set<number>();

    for (const f of findings) {
      if (f.category === 'TRANSPORT' && f.line_number <= 1) {
        continue;
      }
      if (f.line_number >= 1 && f.line_number <= lines.length) {
        const list = findingRulesByLine.get(f.line_number) ?? [];
        if (!list.includes(f.rule_code)) {
          list.push(f.rule_code);
        }
        findingRulesByLine.set(f.line_number, list);

        const start = Math.max(1, f.line_number - contextRadius);
        const end = Math.min(lines.length, f.line_number + contextRadius);
        for (let ln = start; ln <= end; ln++) {
          selectedLineNumbers.add(ln);
        }
      }
    }

    // If no code-line findings were triggered, include first 25 non-empty lines for forensic transparency
    if (selectedLineNumbers.size === 0) {
      const cap = Math.min(lines.length, 25);
      for (let ln = 1; ln <= cap; ln++) {
        selectedLineNumbers.add(ln);
      }
    }

    const sortedLineNums = [...selectedLineNumbers].sort((a, b) => a - b).slice(0, maxPreviewLines);

    return sortedLineNums.map((ln) => {
      const rawContent = lines[ln - 1] ?? '';
      const trimmedRight = rawContent.length > 350 ? `${rawContent.slice(0, 350)}...` : rawContent;
      const rules = findingRulesByLine.get(ln);

      const previewItem: SourcePreviewLine = {
        line: ln,
        content: trimmedRight,
        has_finding: Boolean(rules && rules.length > 0)
      };
      if (rules && rules.length > 0) {
        previewItem.rule_codes = rules;
      }
      return previewItem;
    });
  }

  /**
   * Builds the deterministic evidence_payload object and computes its SHA-256 hex digest.
   * Any third party running SHA-256 over JSON.stringify(evidence_payload) gets the exact same hash.
   */
  static async generateCanonicalIntegrity(params: {
    scanId: string;
    targetUrl: string;
    finalUrl: string;
    targetDomain: string;
    scannedAt: string;
    transport: TransportAudit;
    riskScore: number;
    riskLevel: RiskLevel;
    findings: ScanFinding[];
  }): Promise<{ evidencePayload: CanonicalEvidencePayload; integritySha256: string }> {
    const evidencePayload: CanonicalEvidencePayload = {
      scan_id: params.scanId,
      target_url: params.targetUrl,
      final_url: params.finalUrl,
      target_domain: params.targetDomain,
      scanned_at: params.scannedAt,
      protocol: params.transport.protocol,
      http_status_code: params.transport.http_status_code,
      redirect_count: params.transport.redirect_count,
      security_headers: {
        strict_transport_security: params.transport.security_headers.strict_transport_security,
        content_security_policy: params.transport.security_headers.content_security_policy,
        x_frame_options: params.transport.security_headers.x_frame_options
      },
      risk_score: params.riskScore,
      risk_level: params.riskLevel,
      findings: params.findings.map((f) => ({
        rule_code: f.rule_code,
        category: f.category,
        severity: f.severity,
        line_number: f.line_number,
        column_number: f.column_number,
        dom_selector: f.dom_selector,
        code_snippet: f.code_snippet
      }))
    };

    const canonicalJson = JSON.stringify(evidencePayload);
    const integritySha256 = await CryptoService.sha256Hex(canonicalJson);

    return { evidencePayload, integritySha256 };
  }
}
