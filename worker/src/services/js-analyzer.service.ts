import type { ScanFindingDTO } from '../types.ts';
import { CryptoService } from './crypto.service.ts';

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

export class JsAnalyzerService {
  static analyzeScripts(html: string, isPageHttps: boolean): ScanFindingDTO[] {
    const findings: ScanFindingDTO[] = [];
    if (!html) return findings;

    const lines = html.split(/\r?\n/);
    const scriptBlockRegex = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;

    let match: RegExpExecArray | null;
    let scriptIndex = 0;

    while ((match = scriptBlockRegex.exec(html)) !== null) {
      scriptIndex++;
      const attrsRaw = match[1] || '';
      const scriptBody = match[2] || '';
      const selector = `script:nth-of-type(${scriptIndex})`;
      const blockStartPos = getLineAndColumn(html, match.index);

      // 1. External script over insecure HTTP when page is HTTPS (or external suspicious script)
      const srcMatch = attrsRaw.match(/\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
      const srcVal = srcMatch ? (srcMatch[1] ?? srcMatch[2] ?? srcMatch[3] ?? '') : '';
      if (srcVal && srcVal.toLowerCase().startsWith('http://')) {
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'INSECURE_EXTERNAL_SCRIPT',
          category: 'JS_SCRIPT',
          severity: isPageHttps ? 'CRITICAL' : 'MEDIUM',
          line_number: blockStartPos.line,
          column_number: blockStartPos.column,
          dom_selector: selector,
          citizen_explanation:
            'La página carga programas ocultos desde una dirección insegura sin candado, permitiendo que terceros alteren lo que ves.',
          technical_detail: `Carga de script externo sobre canal sin cifrar (${srcVal}).`,
          code_snippet: (lines[blockStartPos.line - 1] || match[0]).trim().slice(0, 240),
        });
      }

      if (!scriptBody.trim()) continue;

      const bodyStartOffset = match.index + match[0].indexOf(scriptBody);

      // 2. Keylogger / Live Input Exfiltration detection
      const listenerRegex = /\baddEventListener\s*\(\s*["'](keyup|keydown|keypress|input|blur|change)["']/i;
      const exfilRegex = /\b(fetch|XMLHttpRequest|sendBeacon|WebSocket)\b/i;

      const listenerMatch = listenerRegex.exec(scriptBody);
      const exfilMatch = exfilRegex.exec(scriptBody);

      if (listenerMatch && exfilMatch) {
        const targetOffset = bodyStartOffset + exfilMatch.index;
        const pos = getLineAndColumn(html, targetOffset);
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'SUSPICIOUS_KEYLOGGER_EXFILTRATION',
          category: 'JS_SCRIPT',
          severity: 'CRITICAL',
          line_number: pos.line,
          column_number: pos.column,
          dom_selector: selector,
          citizen_explanation:
            '¡Cuidado! Hay un espía invisible en esta página que graba las letras y números que escribes en tiempo real, incluso si no pulsas Enviar.',
          technical_detail: `Listener de eventos de teclado/entrada (${listenerMatch[1]}) acoplado con exfiltración de red asíncrona (${exfilMatch[1]}).`,
          code_snippet: (lines[pos.line - 1] || '').trim().slice(0, 240),
        });
      }

      // 3. Obfuscation / Hidden Payload Execution (eval, atob, fromCharCode)
      const obfuscationRegex = /\b(eval\s*\(|atob\s*\(|String\.fromCharCode\s*\(|new\s+Function\s*\()/;
      const obfMatch = obfuscationRegex.exec(scriptBody);
      if (obfMatch) {
        const targetOffset = bodyStartOffset + obfMatch.index;
        const pos = getLineAndColumn(html, targetOffset);
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'OBFUSCATED_SCRIPT_EXECUTION',
          category: 'JS_SCRIPT',
          severity: 'HIGH',
          line_number: pos.line,
          column_number: pos.column,
          dom_selector: selector,
          citizen_explanation:
            'Esta página esconde direcciones o instrucciones disfrazadas en su código para intentar engañar a los controles de seguridad.',
          technical_detail: `Uso de primitivas de decodificación/ejecución dinámica asociadas a ofuscación (${obfMatch[1].replace('(', '')}).`,
          code_snippet: (lines[pos.line - 1] || '').trim().slice(0, 240),
        });
      }
    }

    return findings;
  }
}
