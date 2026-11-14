import type { ScanFindingDTO } from '../types.ts';
import { CryptoService } from './crypto.service.ts';

interface AttributeMap {
  [key: string]: string;
}

function parseAttributes(tagSource: string): AttributeMap {
  const attrs: AttributeMap = {};
  const attrRegex = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  // Skip tag name
  const withoutTag = tagSource.replace(/^<\s*[a-zA-Z0-9_-]+/, '');
  let match: RegExpExecArray | null;
  while ((match = attrRegex.exec(withoutTag)) !== null) {
    const key = match[1].toLowerCase();
    const val = match[2] ?? match[3] ?? match[4] ?? '';
    attrs[key] = val;
  }
  return attrs;
}

function getLineAndColumn(fullText: string, index: number): { line: number; column: number } {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < index; i++) {
    if (fullText.charCodeAt(i) === 10) {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: index - lastNewline };
}

function extractLineSnippet(lines: string[], lineNumber: number): string {
  const raw = lines[lineNumber - 1] ?? '';
  return raw.trim().slice(0, 260);
}

export class DomParserService {
  private static readonly SENSITIVE_KEYWORDS =
    /(pass|clave|contrase|pwd|pin|card|tarjeta|ccnum|cvv|cvc|cedula|dni|documento|ssn|token|otp|cuenta)/i;

  private static readonly PASSWORD_KEYWORDS =
    /(pass|clave|contrase|pwd|pin)/i;

  private static readonly FINANCIAL_KEYWORDS =
    /(card|tarjeta|ccnum|cvv|cvc)/i;

  static analyzeHtml(
    html: string,
    pageOriginUrl: string,
    isPageHttps: boolean
  ): ScanFindingDTO[] {
    const findings: ScanFindingDTO[] = [];
    if (!html) return findings;

    const lines = html.split(/\r?\n/);
    let pageHost = '';
    try {
      pageHost = new URL(pageOriginUrl).hostname.toLowerCase();
    } catch {
      pageHost = '';
    }

    // 1. Inspect <form ...> blocks and their inner inputs
    const formBlockRegex = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
    let formMatch: RegExpExecArray | null;
    let formIndex = 0;

    while ((formMatch = formBlockRegex.exec(html)) !== null) {
      formIndex++;
      const fullFormHtml = formMatch[0];
      const openTagMatch = fullFormHtml.match(/^<form\b[^>]*>/i);
      if (!openTagMatch) continue;

      const openTag = openTagMatch[0];
      const attrs = parseAttributes(openTag);
      const pos = getLineAndColumn(html, formMatch.index);
      const selector = attrs.id
        ? `form#${attrs.id}`
        : attrs.name
        ? `form[name="${attrs.name}"]`
        : `form:nth-of-type(${formIndex})`;

      const snippet = extractLineSnippet(lines, pos.line) || openTag.slice(0, 240);
      const actionRaw = (attrs.action || '').trim();

      // Check if form contains sensitive inputs
      const hasSensitiveInputs = this.formContainsSensitiveInputs(fullFormHtml);

      // Rule A: Sensitive form served over plain HTTP or submitting to http://
      const submitsOverHttp = actionRaw.toLowerCase().startsWith('http://');
      if ((!isPageHttps && hasSensitiveInputs) || submitsOverHttp) {
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'INSECURE_HTTP_SENSITIVE_FORM',
          category: 'DOM_FORM',
          severity: 'CRITICAL',
          line_number: pos.line,
          column_number: pos.column,
          dom_selector: selector,
          citizen_explanation:
            'Este formulario pide datos privados o bancarios sin candado de seguridad; lo que escribas viaja abierto por internet como una postal sin sobre.',
          technical_detail: submitsOverHttp
            ? `El formulario envía datos explícitamente mediante protocolo sin cifrar (${actionRaw}).`
            : 'Formulario con campos sensibles de credenciales/finanzas servido sobre conexión HTTP sin TLS.',
          code_snippet: snippet,
        });
      }

      // Rule B: Form action pointing to an external / cross-domain server
      if (actionRaw && /^https?:\/\//i.test(actionRaw)) {
        try {
          const actionUrl = new URL(actionRaw);
          const actionHost = actionUrl.hostname.toLowerCase();
          if (pageHost && actionHost !== pageHost && !this.isSameRootDomain(pageHost, actionHost)) {
            findings.push({
              id: CryptoService.generateUlid('fnd'),
              rule_code: 'CROSS_DOMAIN_FORM_ACTION',
              category: 'DOM_FORM',
              severity: hasSensitiveInputs ? 'CRITICAL' : 'HIGH',
              line_number: pos.line,
              column_number: pos.column,
              dom_selector: selector,
              citizen_explanation: `Los datos que escribas aquí no van a esta página: se envían en secreto a otro servidor externo (${actionHost}).`,
              technical_detail: `El atributo action del formulario apunta a un dominio externo distinto al origen (${actionHost} != ${pageHost}).`,
              code_snippet: snippet,
            });
          }
        } catch {
          // Ignore malformed relative URLs
        }
      }
    }

    // 2. Inspect individual <input ...> elements across the document
    const inputRegex = /<input\b[^>]*>/gi;
    let inputMatch: RegExpExecArray | null;
    let inputIndex = 0;

    while ((inputMatch = inputRegex.exec(html)) !== null) {
      inputIndex++;
      const inputTag = inputMatch[0];
      const attrs = parseAttributes(inputTag);
      const type = (attrs.type || 'text').toLowerCase();
      const nameOrId = `${attrs.name || ''} ${attrs.id || ''} ${attrs.placeholder || ''}`;
      const pos = getLineAndColumn(html, inputMatch.index);
      const selector = attrs.id
        ? `input#${attrs.id}`
        : attrs.name
        ? `input[name="${attrs.name}"]`
        : `input:nth-of-type(${inputIndex})`;
      const snippet = extractLineSnippet(lines, pos.line) || inputTag.slice(0, 240);

      // Rule C: Password or PIN asked inside a plain type="text" field (unmasked credential trap)
      if (type === 'text' && this.PASSWORD_KEYWORDS.test(nameOrId)) {
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'PLAINTEXT_PASSWORD_INPUT',
          category: 'DOM_INPUT',
          severity: isPageHttps ? 'HIGH' : 'CRITICAL',
          line_number: pos.line,
          column_number: pos.column,
          dom_selector: selector,
          citizen_explanation:
            'El recuadro donde te piden tu clave ni siquiera oculta las letras con puntos, una técnica común en páginas falsas hechas rápido.',
          technical_detail:
            'Campo con semántica de contraseña o PIN declarado como type="text" en lugar de type="password".',
          code_snippet: snippet,
        });
      }

      // Rule D: Credit card / CVV input on insecure HTTP page
      if (!isPageHttps && this.FINANCIAL_KEYWORDS.test(nameOrId) && type !== 'hidden') {
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'UNENCRYPTED_PAYMENT_CARD_INPUT',
          category: 'DOM_INPUT',
          severity: 'CRITICAL',
          line_number: pos.line,
          column_number: pos.column,
          dom_selector: selector,
          citizen_explanation:
            'Esta casilla solicita datos de tu tarjeta bancaria o código CVV en una página sin protección; cualquier atacante podría copiar tu tarjeta.',
          technical_detail:
            'Campo de captura de numeración de tarjeta o código de seguridad CVV expuesto sin cifrado HTTPS.',
          code_snippet: snippet,
        });
      }
    }

    return findings;
  }

  private static formContainsSensitiveInputs(formHtml: string): boolean {
    if (/type\s*=\s*["']?password["']?/i.test(formHtml)) {
      return true;
    }
    return this.SENSITIVE_KEYWORDS.test(formHtml);
  }

  private static isSameRootDomain(hostA: string, hostB: string): boolean {
    const partsA = hostA.split('.');
    const partsB = hostB.split('.');
    if (partsA.length < 2 || partsB.length < 2) return hostA === hostB;
    const rootA = partsA.slice(-2).join('.');
    const rootB = partsB.slice(-2).join('.');
    return rootA === rootB;
  }
}
