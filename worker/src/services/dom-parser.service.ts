import { ScanFinding } from '../types/models';
import { generateUlid } from '../utils/ulid';
import { extractRegistrableDomain } from './transport.service';

const TRUSTED_EXTERNAL_PROVIDERS = new Set([
  'accounts.google.com',
  'login.microsoftonline.com',
  'appleid.apple.com',
  'checkout.stripe.com',
  'stripe.com',
  'paypal.com',
  'www.paypal.com',
  'mercadopago.com',
  'mercadopago.com.ar',
  'mercadopago.com.co',
  'mercadopago.com.mx',
  'mercadopago.com.pe',
  'placetopay.com',
  'wompi.co',
  'payulatam.com',
  'auth0.com',
  'okta.com'
]);

const PASSWORD_KEYWORDS_REGEX =
  /\b(pass|passwd|password|pwd|clave|contrasena|contraseña|pin|nip|cvv|cvc|cvv2|codigo_seguridad|security_code|otp|token_dinamico)\b/i;

const SENSITIVE_FIELD_REGEX =
  /\b(pass|passwd|password|pwd|clave|contrasena|contraseña|pin|nip|cvv|cvc|card|tarjeta|ccnumber|cc_num|pan|cedula|dni|rut|curp|ssn|documento|identidad|cuenta|iban|otp|token)\b/i;

const SUSPICIOUS_HIDDEN_NAME_REGEX =
  /\b(redirect|redirect_uri|return_url|next_url|webhook|telegram|chat_id|bot_token|exfil|callback_url|victim|ip_addr)\b/i;

export interface LineIndexMap {
  normalizedHtml: string;
  lines: string[];
  lineOffsets: number[];
}

export function buildLineIndexMap(rawHtml: string): LineIndexMap {
  const normalizedHtml = rawHtml.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const lines = normalizedHtml.split('\n');
  const lineOffsets: number[] = new Array<number>(lines.length);

  let currentOffset = 0;
  for (let i = 0; i < lines.length; i++) {
    lineOffsets[i] = currentOffset;
    currentOffset += lines[i]!.length + 1;
  }

  return { normalizedHtml, lines, lineOffsets };
}

export function offsetToLocation(
  indexMap: LineIndexMap,
  charOffset: number
): { lineNumber: number; columnNumber: number; lineContent: string } {
  const { lineOffsets, lines } = indexMap;
  let low = 0;
  let high = lineOffsets.length - 1;

  while (low <= high) {
    const mid = (low + high) >>> 1;
    const midOffset = lineOffsets[mid]!;
    if (midOffset === charOffset) {
      low = mid + 1;
      break;
    } else if (midOffset < charOffset) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  const lineIdx = Math.max(0, low - 1);
  const lineStart = lineOffsets[lineIdx] ?? 0;
  return {
    lineNumber: lineIdx + 1,
    columnNumber: Math.max(1, charOffset - lineStart + 1),
    lineContent: (lines[lineIdx] ?? '').trim()
  };
}

/**
 * Replaces HTML comments and <script>/<style> bodies with spaces of identical byte/char length
 * so DOM tag regexes preserve exact line & column offsets without matching JS strings or comments.
 */
function maskNonDomRegions(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi, (_full, open: string, body: string, close: string) => {
      return open + body.replace(/[^\n]/g, ' ') + close;
    })
    .replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi, (_full, open: string, body: string, close: string) => {
      return open + body.replace(/[^\n]/g, ' ') + close;
    });
}

function parseAttributes(tagMarkup: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const attrRegex = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  // Strip opening `<tagName` and closing `>`
  const inner = tagMarkup.replace(/^<[a-zA-Z0-9:-]+\s*/, '').replace(/\/?>$/, '');

  let match: RegExpExecArray | null;
  while ((match = attrRegex.exec(inner)) !== null) {
    const attrName = match[1]!.toLowerCase();
    const attrVal = match[2] ?? match[3] ?? match[4] ?? '';
    attrs[attrName] = attrVal;
  }
  return attrs;
}

function buildTagSelector(
  tagName: string,
  attrs: Record<string, string>,
  nthIndex: number,
  parentSelector?: string
): string {
  let base = tagName.toLowerCase();
  if (attrs.id && /^[a-zA-Z0-9_-]+$/.test(attrs.id)) {
    base += `#${attrs.id}`;
  } else if (attrs.name && /^[a-zA-Z0-9_.\-[\]]+$/.test(attrs.name)) {
    base += `[name="${attrs.name}"]`;
  } else if (attrs.class) {
    const firstClass = attrs.class
      .trim()
      .split(/\s+/)
      .find((c) => /^[a-zA-Z0-9_-]+$/.test(c));
    if (firstClass) {
      base += `.${firstClass}:nth-of-type(${nthIndex})`;
    } else {
      base += `:nth-of-type(${nthIndex})`;
    }
  } else {
    base += `:nth-of-type(${nthIndex})`;
  }

  return parentSelector ? `${parentSelector} > ${base}` : base;
}

function truncateSnippet(raw: string, maxLen = 220): string {
  const singleLine = raw.replace(/\s+/g, ' ').trim();
  return singleLine.length > maxLen ? `${singleLine.slice(0, maxLen)}...` : singleLine;
}

function isTrustedExternalDomain(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (TRUSTED_EXTERNAL_PROVIDERS.has(lower)) return true;
  const reg = extractRegistrableDomain(lower);
  return TRUSTED_EXTERNAL_PROVIDERS.has(reg);
}

interface ParsedInputInfo {
  offset: number;
  tagMarkup: string;
  attrs: Record<string, string>;
  type: string;
  isSensitive: boolean;
  isPasswordLike: boolean;
  selector: string;
}

export class DomParserService {
  static analyzeHtml(html: string, pageUrl: URL): {
    findings: ScanFinding[];
    indexMap: LineIndexMap;
  } {
    const indexMap = buildLineIndexMap(html);
    const maskedHtml = maskNonDomRegions(indexMap.normalizedHtml);
    const findings: ScanFinding[] = [];

    const pageIsHttps = pageUrl.protocol === 'https:';
    const pageDomain = pageUrl.hostname.toLowerCase();
    const pageRootDomain = extractRegistrableDomain(pageDomain);

    // Track character intervals covered by <form>...</form> so standalone <input> fields are also audited
    const formIntervals: Array<{ start: number; end: number }> = [];

    const formRegex = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
    let formMatch: RegExpExecArray | null;
    let formCounter = 0;

    while ((formMatch = formRegex.exec(maskedHtml)) !== null) {
      formCounter++;
      const formStartOffset = formMatch.index;
      const formBlockMasked = formMatch[0]!;
      const formEndOffset = formStartOffset + formBlockMasked.length;
      formIntervals.push({ start: formStartOffset, end: formEndOffset });

      const openTagMatch = /^<form\b[^>]*>/i.exec(formBlockMasked);
      if (!openTagMatch) continue;

      const originalOpenTag = indexMap.normalizedHtml.slice(
        formStartOffset,
        formStartOffset + openTagMatch[0]!.length
      );
      const formAttrs = parseAttributes(originalOpenTag);
      const formSelector = buildTagSelector('form', formAttrs, formCounter);
      const formLoc = offsetToLocation(indexMap, formStartOffset);

      // Parse all <input> elements inside this form
      const inputsInForm = this.extractInputsInRegion(
        maskedHtml,
        indexMap.normalizedHtml,
        formStartOffset,
        formEndOffset,
        formSelector
      );

      const hasSensitiveInput = inputsInForm.some((inp) => inp.isSensitive);
      const rawAction = (formAttrs.action ?? '').trim();

      // Audit form action target
      let resolvedActionUrl: URL | null = null;
      if (
        rawAction &&
        !rawAction.toLowerCase().startsWith('javascript:') &&
        !rawAction.toLowerCase().startsWith('mailto:')
      ) {
        try {
          resolvedActionUrl = new URL(rawAction, pageUrl);
        } catch {
          resolvedActionUrl = null;
        }
      }

      // 1. Check mailto: credential exfiltration
      if (rawAction.toLowerCase().startsWith('mailto:') && hasSensitiveInput) {
        findings.push({
          id: generateUlid('fnd'),
          rule_code: 'MAILTO_FORM_EXFILTRATION',
          category: 'DOM_FORM',
          severity: 'CRITICAL',
          line_number: formLoc.lineNumber,
          column_number: formLoc.columnNumber,
          dom_selector: formSelector,
          citizen_explanation:
            'Este formulario intenta enviar tus datos directamente a una dirección de correo electrónico en lugar de un sistema seguro.',
          technical_detail: `Formulario con campos sensibles utiliza esquema inseguro '${rawAction}' en el atributo action.`,
          code_snippet: truncateSnippet(originalOpenTag)
        });
      }

      // 2. Check INSECURE_HTTP_SENSITIVE_FORM (page over HTTP or action pointing to http://)
      const actionIsHttp = resolvedActionUrl
        ? resolvedActionUrl.protocol === 'http:'
        : !pageIsHttps;

      if (hasSensitiveInput && (!pageIsHttps || actionIsHttp)) {
        findings.push({
          id: generateUlid('fnd'),
          rule_code: 'INSECURE_HTTP_SENSITIVE_FORM',
          category: 'DOM_FORM',
          severity: 'CRITICAL',
          line_number: formLoc.lineNumber,
          column_number: formLoc.columnNumber,
          dom_selector: formSelector,
          citizen_explanation:
            'Este formulario pide tu contraseña o datos sensibles sobre una conexión HTTP sin cifrar; cualquier persona en la misma red Wi-Fi puede interceptarla.',
          technical_detail: !pageIsHttps
            ? `Etiqueta <form> con campos sensibles servida bajo esquema http:// (${pageUrl.origin})${resolvedActionUrl ? ` y action hacia ${resolvedActionUrl.origin}` : ''}.`
            : `La página carga en HTTPS pero el atributo action del formulario envía los datos en texto plano hacia '${resolvedActionUrl?.toString() || rawAction}'.`,
          code_snippet: truncateSnippet(originalOpenTag)
        });
      }

      // 3. Check CROSS_DOMAIN_FORM_ACTION
      if (resolvedActionUrl && (resolvedActionUrl.protocol === 'http:' || resolvedActionUrl.protocol === 'https:')) {
        const destDomain = resolvedActionUrl.hostname.toLowerCase();
        const destRootDomain = extractRegistrableDomain(destDomain);

        if (destRootDomain !== pageRootDomain) {
          if (resolvedActionUrl.protocol === 'https:' && isTrustedExternalDomain(destDomain)) {
            findings.push({
              id: generateUlid('fnd'),
              rule_code: 'TRUSTED_EXTERNAL_FORM_PROVIDER',
              category: 'DOM_FORM',
              severity: 'LOW',
              line_number: formLoc.lineNumber,
              column_number: formLoc.columnNumber,
              dom_selector: formSelector,
              citizen_explanation: `Este formulario delega el proceso hacia una pasarela externa reconocida (${destDomain}). Verifica siempre el dominio antes de continuar.`,
              technical_detail: `Envío cross-domain desde '${pageDomain}' hacia proveedor reconocido en lista blanca '${destDomain}' sobre HTTPS.`,
              code_snippet: truncateSnippet(originalOpenTag)
            });
          } else {
            findings.push({
              id: generateUlid('fnd'),
              rule_code: 'CROSS_DOMAIN_FORM_ACTION',
              category: 'DOM_FORM',
              severity: hasSensitiveInput ? 'CRITICAL' : 'HIGH',
              line_number: formLoc.lineNumber,
              column_number: formLoc.columnNumber,
              dom_selector: formSelector,
              citizen_explanation: `Los datos que escribas aquí se envían directamente a otro sitio web externo (${destDomain}) distinto a la página que estás viendo (${pageDomain}).`,
              technical_detail: `Origen '${pageDomain}' (raíz: ${pageRootDomain}) difiere del destino de exfiltración '${destDomain}' (raíz: ${destRootDomain}) en el atributo action.`,
              code_snippet: truncateSnippet(originalOpenTag)
            });
          }
        }
      }

      // 4. Audit individual inputs inside the form
      this.auditInputs(inputsInForm, indexMap, pageIsHttps, findings);
    }

    // Also audit standalone <input> elements outside any <form> (common in JS-driven phishing kits)
    const allStandaloneInputs = this.extractStandaloneInputs(
      maskedHtml,
      indexMap.normalizedHtml,
      formIntervals
    );

    if (allStandaloneInputs.length > 0) {
      for (const inp of allStandaloneInputs) {
        if (inp.isSensitive && !pageIsHttps) {
          const loc = offsetToLocation(indexMap, inp.offset);
          findings.push({
            id: generateUlid('fnd'),
            rule_code: 'INSECURE_HTTP_SENSITIVE_INPUT',
            category: 'DOM_INPUT',
            severity: 'CRITICAL',
            line_number: loc.lineNumber,
            column_number: loc.columnNumber,
            dom_selector: inp.selector,
            citizen_explanation:
              'Esta página solicita contraseñas, tarjetas o datos personales sin conexión cifrada HTTPS y sin un formulario estándar.',
            technical_detail: `Campo sensible (${inp.selector}) fuera de <form> servido en texto plano sobre http://.`,
            code_snippet: truncateSnippet(inp.tagMarkup)
          });
        }
      }
      this.auditInputs(allStandaloneInputs, indexMap, pageIsHttps, findings);
    }

    return { findings, indexMap };
  }

  private static extractInputsInRegion(
    maskedHtml: string,
    originalHtml: string,
    startOffset: number,
    endOffset: number,
    parentSelector?: string
  ): ParsedInputInfo[] {
    const regionMasked = maskedHtml.slice(startOffset, endOffset);
    const inputRegex = /<input\b[^>]*>/gi;
    const results: ParsedInputInfo[] = [];

    let match: RegExpExecArray | null;
    let idx = 0;
    while ((match = inputRegex.exec(regionMasked)) !== null) {
      idx++;
      const absOffset = startOffset + match.index;
      const originalTag = originalHtml.slice(absOffset, absOffset + match[0]!.length);
      const attrs = parseAttributes(originalTag);
      const type = (attrs.type ?? 'text').toLowerCase().trim();

      const descriptorText = [
        attrs.name ?? '',
        attrs.id ?? '',
        attrs.placeholder ?? '',
        attrs.autocomplete ?? '',
        attrs['aria-label'] ?? ''
      ].join(' ');

      const isPasswordLike =
        type === 'password' || PASSWORD_KEYWORDS_REGEX.test(descriptorText);
      const isSensitive =
        isPasswordLike ||
        type === 'email' ||
        type === 'tel' ||
        SENSITIVE_FIELD_REGEX.test(descriptorText);

      results.push({
        offset: absOffset,
        tagMarkup: originalTag,
        attrs,
        type,
        isSensitive,
        isPasswordLike,
        selector: buildTagSelector('input', attrs, idx, parentSelector)
      });
    }

    return results;
  }

  private static extractStandaloneInputs(
    maskedHtml: string,
    originalHtml: string,
    formIntervals: Array<{ start: number; end: number }>
  ): ParsedInputInfo[] {
    const inputRegex = /<input\b[^>]*>/gi;
    const standalone: ParsedInputInfo[] = [];

    let match: RegExpExecArray | null;
    let idx = 0;
    while ((match = inputRegex.exec(maskedHtml)) !== null) {
      const absOffset = match.index;
      const insideForm = formIntervals.some(
        (interval) => absOffset >= interval.start && absOffset < interval.end
      );
      if (insideForm) continue;

      idx++;
      const originalTag = originalHtml.slice(absOffset, absOffset + match[0]!.length);
      const attrs = parseAttributes(originalTag);
      const type = (attrs.type ?? 'text').toLowerCase().trim();
      const descriptorText = [
        attrs.name ?? '',
        attrs.id ?? '',
        attrs.placeholder ?? '',
        attrs.autocomplete ?? '',
        attrs['aria-label'] ?? ''
      ].join(' ');

      const isPasswordLike =
        type === 'password' || PASSWORD_KEYWORDS_REGEX.test(descriptorText);
      const isSensitive = isPasswordLike || SENSITIVE_FIELD_REGEX.test(descriptorText);

      standalone.push({
        offset: absOffset,
        tagMarkup: originalTag,
        attrs,
        type,
        isSensitive,
        isPasswordLike,
        selector: buildTagSelector('input', attrs, idx)
      });
    }

    return standalone;
  }

  private static auditInputs(
    inputs: ParsedInputInfo[],
    indexMap: LineIndexMap,
    pageIsHttps: boolean,
    findings: ScanFinding[]
  ): void {
    for (const inp of inputs) {
      const loc = offsetToLocation(indexMap, inp.offset);

      // 1. Disguised / unmasked password or CVV/PIN field using type="text" or type="number" without masking
      if (
        (inp.type === 'text' || inp.type === '') &&
        PASSWORD_KEYWORDS_REGEX.test(
          `${inp.attrs.name ?? ''} ${inp.attrs.id ?? ''} ${inp.attrs.placeholder ?? ''}`
        )
      ) {
        findings.push({
          id: generateUlid('fnd'),
          rule_code: 'UNMASKED_PASSWORD_INPUT',
          category: 'DOM_INPUT',
          severity: 'HIGH',
          line_number: loc.lineNumber,
          column_number: loc.columnNumber,
          dom_selector: inp.selector,
          citizen_explanation:
            'El campo de contraseña, PIN o código de seguridad no oculta los caracteres con puntos (type="text"), exponiendo tu clave en pantalla y autocompletado.',
          technical_detail: `Campo sensible detectado con type="${inp.type || 'text'}" en lugar de type="password" o enmascaramiento seguro.`,
          code_snippet: truncateSnippet(inp.tagMarkup)
        });
      }

      // 2. Password input on non-HTTPS page (explicit input-level trace)
      if (inp.type === 'password' && !pageIsHttps) {
        findings.push({
          id: generateUlid('fnd'),
          rule_code: 'PLAINTEXT_PASSWORD_FIELD',
          category: 'DOM_INPUT',
          severity: 'CRITICAL',
          line_number: loc.lineNumber,
          column_number: loc.columnNumber,
          dom_selector: inp.selector,
          citizen_explanation:
            'Este campo captura tu contraseña en una página sin candado de seguridad HTTPS.',
          technical_detail: `Elemento <input type="password"> renderizado sobre documento HTTP sin transporte TLS.`,
          code_snippet: truncateSnippet(inp.tagMarkup)
        });
      }

      // 3. Suspicious <input type="hidden"> auditing
      if (inp.type === 'hidden') {
        const hiddenName = inp.attrs.name ?? inp.attrs.id ?? '';
        const hiddenVal = inp.attrs.value ?? '';

        const hasExternalUrlValue = /^https?:\/\//i.test(hiddenVal);
        const hasLongEncodedPayload =
          hiddenVal.length >= 64 && /^[A-Za-z0-9+/=_-]+$/.test(hiddenVal);
        const hasSuspiciousName = SUSPICIOUS_HIDDEN_NAME_REGEX.test(hiddenName);

        if (
          (hasSuspiciousName && (hasExternalUrlValue || hiddenVal.length > 0)) ||
          (hasExternalUrlValue && hiddenName.toLowerCase().includes('url'))
        ) {
          findings.push({
            id: generateUlid('fnd'),
            rule_code: 'SUSPICIOUS_HIDDEN_INPUT',
            category: 'DOM_INPUT',
            severity: hasExternalUrlValue ? 'MEDIUM' : 'LOW',
            line_number: loc.lineNumber,
            column_number: loc.columnNumber,
            dom_selector: inp.selector,
            citizen_explanation:
              'El formulario incluye parámetros ocultos que redirigen la navegación o adjuntan identificadores invisibles al enviar tus datos.',
            technical_detail: `Campo oculto <input type="hidden"> con nombre '${hiddenName || '(sin nombre)'}' y valor sospechoso (${hasLongEncodedPayload ? 'token codificado extenso' : 'parámetro de redirección/control'}).`,
            code_snippet: truncateSnippet(inp.tagMarkup)
          });
        }
      }
    }
  }
}
