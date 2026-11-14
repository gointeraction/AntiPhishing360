import { ScanFinding } from '../types/models';
import { generateUlid } from '../utils/ulid';
import { LineIndexMap, offsetToLocation } from './dom-parser.service';
import { parseIPv4 } from './ssrf-guard.service';
import { extractRegistrableDomain } from './transport.service';

const EVENT_CAPTURE_REGEX =
  /\b(?:addEventListener\s*\(\s*['"`](?:keyup|keydown|keypress|input|blur|change|submit)['"`]|\.on(?:keyup|keydown|keypress|blur|change|submit)\s*=)/i;

const NETWORK_SINK_REGEX =
  /\b(?:fetch\s*\(|new\s+XMLHttpRequest\b|navigator\.sendBeacon\s*\(|new\s+WebSocket\s*\(|axios\.(?:post|get|request)\s*\(|\$\.(?:ajax|post)\s*\()/i;

const TELEGRAM_OR_DISCORD_C2_REGEX =
  /https?:\/\/(?:api\.telegram\.org\/bot[0-9]{6,}:[A-Za-z0-9_-]+|(?:\w+\.)?discord(?:app)?\.com\/api\/webhooks\/\d+)/i;

const OBFUSCATION_CALL_REGEX =
  /\b(?:eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]|document\.write\s*\(\s*(?:unescape|atob)\s*\(|String\.fromCharCode\s*\((?:[^)]*,){4,})/i;

const EVAL_ATOB_CHAIN_REGEX = /\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/i;

const LONG_ENCODED_STRING_REGEX =
  /['"`](?:[A-Za-z0-9+/]{100,}={0,2}|(?:\\x[0-9a-fA-F]{2}){25,}|(?:\\u[0-9a-fA-F]{4}){25,}|[0-9a-fA-F]{120,})['"`]/;

const ANTI_DEVTOOLS_REGEX =
  /addEventListener\s*\(\s*['"`]contextmenu['"`][\s\S]{0,120}preventDefault\s*\(|keyCode\s*===\s*123|\bdebugger\b/i;

const HIGH_RISK_SCRIPT_TLDS = ['.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.su', '.zip', '.icu'];

function parseScriptAttributes(openTag: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const attrRegex = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  const inner = openTag.replace(/^<script\b\s*/i, '').replace(/\/?>$/, '');

  let match: RegExpExecArray | null;
  while ((match = attrRegex.exec(inner)) !== null) {
    attrs[match[1]!.toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? '';
  }
  return attrs;
}

function truncateJsLine(line: string, maxLen = 220): string {
  const clean = line.trim();
  return clean.length > maxLen ? `${clean.slice(0, maxLen)}...` : clean;
}

export class JsAnalyzerService {
  static analyzeScripts(indexMap: LineIndexMap, pageUrl: URL): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const html = indexMap.normalizedHtml;
    const pageRootDomain = extractRegistrableDomain(pageUrl.hostname);

    const scriptRegex = /(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi;
    let match: RegExpExecArray | null;
    let scriptIndex = 0;

    while ((match = scriptRegex.exec(html)) !== null) {
      scriptIndex++;
      const blockStartOffset = match.index;
      const openTag = match[1]!;
      const scriptBody = match[2]!;
      const bodyStartOffset = blockStartOffset + openTag.length;

      const attrs = parseScriptAttributes(openTag);
      const selector = attrs.id
        ? `script#${attrs.id}`
        : `script:nth-of-type(${scriptIndex})`;
      const openTagLoc = offsetToLocation(indexMap, blockStartOffset);

      // 1. Audit external <script src="...">
      if (attrs.src) {
        this.auditExternalScriptSrc(
          attrs.src,
          openTag,
          openTagLoc.lineNumber,
          openTagLoc.columnNumber,
          selector,
          pageUrl,
          pageRootDomain,
          findings
        );
      }

      if (!scriptBody.trim()) {
        continue;
      }

      // 2. Direct detection of Telegram Bot API / Discord Webhook C2 credentials in JS
      const c2Match = TELEGRAM_OR_DISCORD_C2_REGEX.exec(scriptBody);
      if (c2Match) {
        const c2Loc = offsetToLocation(indexMap, bodyStartOffset + c2Match.index);
        findings.push({
          id: generateUlid('fnd'),
          rule_code: 'JS_C2_WEBHOOK_EXFILTRATION',
          category: 'JS_SCRIPT',
          severity: 'CRITICAL',
          line_number: c2Loc.lineNumber,
          column_number: c2Loc.columnNumber,
          dom_selector: selector,
          citizen_explanation:
            'El código de esta página envía tus datos robados directamente a un bot privado de Telegram o Discord controlado por atacantes.',
          technical_detail: `Endpoint de comando y control (C2) detectado en bloque ${selector}: '${c2Match[0].slice(0, 55)}...'.`,
          code_snippet: truncateJsLine(c2Loc.lineContent || c2Match[0])
        });
      }

      // 3. Detect Event Listeners + Async Exfiltration to external host
      const eventMatch = EVENT_CAPTURE_REGEX.exec(scriptBody);
      const sinkMatch = NETWORK_SINK_REGEX.exec(scriptBody);

      if (eventMatch && sinkMatch) {
        const externalUrlMatches = [...scriptBody.matchAll(/['"`](https?:\/\/[^'"`\s]+)['"`]/gi)];
        const externalHosts: string[] = [];

        for (const urlMatch of externalUrlMatches) {
          try {
            const candidate = new URL(urlMatch[1]!);
            const candidateRoot = extractRegistrableDomain(candidate.hostname);
            if (candidateRoot !== pageRootDomain) {
              externalHosts.push(candidate.hostname);
            }
          } catch {
            // ignore malformed URL string
          }
        }

        if (externalHosts.length > 0 || /\bbtoa\s*\(/.test(scriptBody)) {
          const primaryOffset = bodyStartOffset + sinkMatch.index;
          const sinkLoc = offsetToLocation(indexMap, primaryOffset);
          const uniqueHosts = [...new Set(externalHosts)];

          findings.push({
            id: generateUlid('fnd'),
            rule_code: 'JS_ASYNC_EXFILTRATION',
            category: 'JS_SCRIPT',
            severity: 'CRITICAL',
            line_number: sinkLoc.lineNumber,
            column_number: sinkLoc.columnNumber,
            dom_selector: selector,
            citizen_explanation:
              'Un script oculto captura lo que escribes en los campos en tiempo real y lo transmite silenciosamente a un servidor externo.',
            technical_detail: `Captura de eventos (${eventMatch[0].trim()}) combinada con llamada de red (${sinkMatch[0].trim()})${uniqueHosts.length > 0 ? ` hacia host externo: ${uniqueHosts.join(', ')}` : ' con codificación btoa()'}.`,
            code_snippet: truncateJsLine(sinkLoc.lineContent)
          });
        }
      }

      // 4. Detect JavaScript Obfuscation (eval/atob, Function, fromCharCode, long Base64/Hex blobs)
      const evalAtobMatch = EVAL_ATOB_CHAIN_REGEX.exec(scriptBody);
      const obfCallMatch = evalAtobMatch ?? OBFUSCATION_CALL_REGEX.exec(scriptBody);
      const encodedBlobMatch = LONG_ENCODED_STRING_REGEX.exec(scriptBody);

      if (obfCallMatch || encodedBlobMatch) {
        const chosenMatch = obfCallMatch ?? encodedBlobMatch!;
        const obfLoc = offsetToLocation(indexMap, bodyStartOffset + chosenMatch.index);

        findings.push({
          id: generateUlid('fnd'),
          rule_code: 'JS_OBFUSCATION_DETECTED',
          category: 'JS_SCRIPT',
          severity: evalAtobMatch ? 'CRITICAL' : 'HIGH',
          line_number: obfLoc.lineNumber,
          column_number: obfLoc.columnNumber,
          dom_selector: selector,
          citizen_explanation:
            'La página contiene código JavaScript camuflado (ofuscado) para esconder sus verdaderas acciones frente a revisiones de seguridad.',
          technical_detail: obfCallMatch
            ? `Patrón de ejecución dinámica/ofuscación detectado (${obfCallMatch[0].trim()}) en ${selector}.`
            : `Cadena codificada en Base64/Hexadecimal mayor a 100 caracteres detectada en ${selector}.`,
          code_snippet: truncateJsLine(obfLoc.lineContent || chosenMatch[0])
        });
      }

      // 5. Detect Anti-Inspection / Anti-Forensics scripts (blocking right click / F12)
      const antiDevMatch = ANTI_DEVTOOLS_REGEX.exec(scriptBody);
      if (antiDevMatch) {
        const antiLoc = offsetToLocation(indexMap, bodyStartOffset + antiDevMatch.index);
        findings.push({
          id: generateUlid('fnd'),
          rule_code: 'JS_ANTI_INSPECTION',
          category: 'JS_SCRIPT',
          severity: 'MEDIUM',
          line_number: antiLoc.lineNumber,
          column_number: antiLoc.columnNumber,
          dom_selector: selector,
          citizen_explanation:
            'El sitio intenta bloquear el clic derecho o las herramientas de inspección del navegador para dificultar que verifiques si es falso.',
          technical_detail: `Rutina anti-análisis detectada en ${selector} (${antiDevMatch[0].slice(0, 60).trim()}).`,
          code_snippet: truncateJsLine(antiLoc.lineContent)
        });
      }
    }

    return findings;
  }

  private static auditExternalScriptSrc(
    rawSrc: string,
    openTag: string,
    lineNumber: number,
    columnNumber: number,
    selector: string,
    pageUrl: URL,
    pageRootDomain: string,
    findings: ScanFinding[]
  ): void {
    let resolvedSrc: URL;
    try {
      resolvedSrc = new URL(rawSrc, pageUrl);
    } catch {
      return;
    }

    // Mixed content / insecure HTTP external script
    if (pageUrl.protocol === 'https:' && resolvedSrc.protocol === 'http:') {
      findings.push({
        id: generateUlid('fnd'),
        rule_code: 'MIXED_CONTENT_INSECURE_SCRIPT',
        category: 'JS_SCRIPT',
        severity: 'HIGH',
        line_number: lineNumber,
        column_number: columnNumber,
        dom_selector: selector,
        citizen_explanation:
          'Aunque la página principal tiene candado HTTPS, carga programas externos sin cifrado que pueden ser alterados en tránsito.',
        technical_detail: `Carga de script externo sobre http:// (${resolvedSrc.toString()}) dentro de un origen HTTPS.`,
        code_snippet: truncateJsLine(openTag)
      });
      return;
    }

    const srcHost = resolvedSrc.hostname.toLowerCase();
    const srcRoot = extractRegistrableDomain(srcHost);
    if (srcRoot !== pageRootDomain) {
      const isRawIp = Boolean(parseIPv4(srcHost));
      const hasRiskyTld = HIGH_RISK_SCRIPT_TLDS.some((tld) => srcHost.endsWith(tld));

      if (isRawIp || hasRiskyTld) {
        findings.push({
          id: generateUlid('fnd'),
          rule_code: 'SUSPICIOUS_EXTERNAL_SCRIPT_HOST',
          category: 'JS_SCRIPT',
          severity: 'HIGH',
          line_number: lineNumber,
          column_number: columnNumber,
          dom_selector: selector,
          citizen_explanation: `La página descarga código ejecutable desde un servidor externo de alto riesgo (${srcHost}).`,
          technical_detail: `Inclusión de script remoto desde ${isRawIp ? 'dirección IP directa' : 'TLD de abuso frecuente'}: ${resolvedSrc.origin}.`,
          code_snippet: truncateJsLine(openTag)
        });
      }
    }
  }
}
