import { RedirectHop, ScanFinding, TransportAudit, UserAgentProfile } from '../types/models';
import { AppError } from '../utils/response';
import { generateUlid } from '../utils/ulid';
import { parseIPv4, SsrfGuardService } from './ssrf-guard.service';

const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT_MS = 5000;
const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2 MB strict memory cap

const USER_AGENTS: Record<UserAgentProfile, string> = {
  mobile_android:
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
  mobile_ios:
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  desktop_chrome:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
};

export interface TransportFetchResult {
  initialUrl: URL;
  finalUrl: URL;
  htmlContent: string;
  audit: TransportAudit;
  findings: ScanFinding[];
}

export function extractRegistrableDomain(hostname: string): string {
  const clean = hostname.toLowerCase().replace(/\.$/, '');
  if (parseIPv4(clean) || clean.startsWith('[')) {
    return clean;
  }
  const parts = clean.split('.');
  if (parts.length <= 2) {
    return clean;
  }
  const secondLevelSuffixes = new Set([
    'com.ar',
    'com.br',
    'com.co',
    'com.ec',
    'com.mx',
    'com.pe',
    'com.uy',
    'com.ve',
    'gob.ec',
    'gob.mx',
    'gob.pe',
    'gov.co',
    'co.uk',
    'org.uk',
    'com.es'
  ]);
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (secondLevelSuffixes.has(lastTwo) && parts.length >= 3) {
    return `${parts[parts.length - 3]}.${lastTwo}`;
  }
  return lastTwo;
}

export class TransportService {
  static async fetchAndAudit(
    rawUrl: string,
    profile: UserAgentProfile = 'mobile_android'
  ): Promise<TransportFetchResult> {
    const initialUrl = await SsrfGuardService.validateTargetUrl(rawUrl, true);
    let currentUrl = initialUrl;
    const redirectChain: RedirectHop[] = [];
    const userAgent = USER_AGENTS[profile] || USER_AGENTS.mobile_android;

    let finalResponse: Response | null = null;
    let downgradedHttpsToHttp = false;

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

      let response: Response;
      try {
        response = await fetch(currentUrl.toString(), {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': userAgent,
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'es-419,es;q=0.9,en;q=0.8',
            'Cache-Control': 'no-cache'
          }
        });
      } catch {
        clearTimeout(timeoutId);
        throw new AppError(
          502,
          'TARGET_UNREACHABLE',
          'No fue posible conectar con el servidor destino dentro del tiempo límite de 5 segundos'
        );
      } finally {
        clearTimeout(timeoutId);
      }

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const locationHeader = response.headers.get('location');
        if (!locationHeader) {
          finalResponse = response;
          break;
        }

        if (hop === MAX_REDIRECTS) {
          throw new AppError(
            502,
            'TOO_MANY_REDIRECTS',
            `El sitio destino excedió el límite máximo de seguridad de ${MAX_REDIRECTS} redirecciones consecutivas`
          );
        }

        let resolvedNext: URL;
        try {
          resolvedNext = new URL(locationHeader, currentUrl);
        } catch {
          throw new AppError(
            502,
            'INVALID_REDIRECT_LOCATION',
            'El servidor destino devolvió una cabecera de redirección malformada'
          );
        }

        // Validate every single redirect hop against SSRF Guard
        const validatedNext = await SsrfGuardService.validateTargetUrl(
          resolvedNext.toString(),
          true
        );

        if (currentUrl.protocol === 'https:' && validatedNext.protocol === 'http:') {
          downgradedHttpsToHttp = true;
        }

        redirectChain.push({
          step: hop + 1,
          from_url: currentUrl.toString(),
          to_url: validatedNext.toString(),
          status_code: response.status
        });

        currentUrl = validatedNext;
        continue;
      }

      finalResponse = response;
      break;
    }

    if (!finalResponse) {
      throw new AppError(
        502,
        'TARGET_UNREACHABLE',
        'No se obtuvo respuesta válida del servidor destino'
      );
    }

    const { text: htmlContent, byteLength } = await this.readStreamBounded(
      finalResponse,
      MAX_HTML_BYTES
    );

    const protocol = currentUrl.protocol === 'https:' ? 'https' : 'http';
    const isHttps = protocol === 'https';

    const hstsHeader = finalResponse.headers.get('strict-transport-security');
    const cspHeader = finalResponse.headers.get('content-security-policy');
    const xfoHeader = finalResponse.headers.get('x-frame-options');
    const xctoHeader = finalResponse.headers.get('x-content-type-options');
    const referrerHeader = finalResponse.headers.get('referrer-policy');
    const contentType = finalResponse.headers.get('content-type') || 'text/html';

    const hasCspFrameAncestors = Boolean(
      cspHeader && cspHeader.toLowerCase().includes('frame-ancestors')
    );

    const audit: TransportAudit = {
      protocol,
      is_https: isHttps,
      http_status_code: finalResponse.status,
      redirect_count: redirectChain.length,
      redirect_chain: redirectChain,
      tls_verified: isHttps,
      content_type: contentType,
      response_bytes: byteLength,
      security_headers: {
        strict_transport_security: Boolean(hstsHeader),
        content_security_policy: Boolean(cspHeader),
        x_frame_options: Boolean(xfoHeader || hasCspFrameAncestors),
        x_content_type_options: Boolean(xctoHeader),
        referrer_policy: Boolean(referrerHeader)
      }
    };

    const findings = this.evaluateTransportFindings(
      initialUrl,
      currentUrl,
      audit,
      downgradedHttpsToHttp
    );

    return {
      initialUrl,
      finalUrl: currentUrl,
      htmlContent,
      audit,
      findings
    };
  }

  private static async readStreamBounded(
    response: Response,
    maxBytes: number
  ): Promise<{ text: string; byteLength: number }> {
    if (!response.body) {
      return { text: '', byteLength: 0 };
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          if (totalBytes + value.byteLength > maxBytes) {
            const allowedSlice = value.subarray(0, maxBytes - totalBytes);
            chunks.push(allowedSlice);
            totalBytes += allowedSlice.byteLength;
            await reader.cancel();
            break;
          }
          chunks.push(value);
          totalBytes += value.byteLength;
        }
      }
    } finally {
      reader.releaseLock();
    }

    const combined = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }

    const decoder = new TextDecoder('utf-8');
    return { text: decoder.decode(combined), byteLength: totalBytes };
  }

  private static evaluateTransportFindings(
    initialUrl: URL,
    finalUrl: URL,
    audit: TransportAudit,
    downgradedHttpsToHttp: boolean
  ): ScanFinding[] {
    const findings: ScanFinding[] = [];

    if (!audit.is_https) {
      findings.push({
        id: generateUlid('fnd'),
        rule_code: 'INSECURE_HTTP_TRANSPORT',
        category: 'TRANSPORT',
        severity: 'HIGH',
        line_number: 1,
        column_number: 1,
        dom_selector: 'document:transport',
        citizen_explanation:
          'Esta página no tiene candado de cifrado real (usa HTTP en lugar de HTTPS). Cualquier dato que envíes viaja expuesto en la red.',
        technical_detail: `El recurso final (${finalUrl.origin}) se sirve sobre esquema http:// en texto plano sin protección TLS.`,
        code_snippet: `GET ${finalUrl.pathname || '/'} HTTP/1.1 | Host: ${finalUrl.host} (Scheme: http://)`
      });
    }

    if (downgradedHttpsToHttp) {
      findings.push({
        id: generateUlid('fnd'),
        rule_code: 'HTTPS_TO_HTTP_DOWNGRADE',
        category: 'TRANSPORT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'document:redirect-chain',
        citizen_explanation:
          'El enlace parecía seguro al inicio (HTTPS), pero te redirigió silenciosamente a una página sin cifrado (HTTP).',
        technical_detail: `Degradación de transporte TLS detectada en la cadena de redirección desde ${initialUrl.origin} hacia ${finalUrl.origin}.`,
        code_snippet: audit.redirect_chain
          .map((h) => `[${h.status_code}] ${h.from_url} -> ${h.to_url}`)
          .join(' | ')
      });
    }

    const distinctDomains = new Set<string>([
      extractRegistrableDomain(initialUrl.hostname),
      ...audit.redirect_chain.map((hop) => {
        try {
          return extractRegistrableDomain(new URL(hop.to_url).hostname);
        } catch {
          return hop.to_url;
        }
      })
    ]);

    if (audit.redirect_count >= 2 && distinctDomains.size >= 2) {
      findings.push({
        id: generateUlid('fnd'),
        rule_code: 'SUSPICIOUS_REDIRECT_CHAIN',
        category: 'TRANSPORT',
        severity: 'MEDIUM',
        line_number: 1,
        column_number: 1,
        dom_selector: 'document:redirect-chain',
        citizen_explanation:
          'El enlace rebota por múltiples dominios distintos antes de abrir la página final, una táctica común para ocultar sitios falsos.',
        technical_detail: `Se detectaron ${audit.redirect_count} saltos HTTP atravesando ${distinctDomains.size} dominios registrables distintos.`,
        code_snippet: `${initialUrl.hostname} => ${finalUrl.hostname} (${audit.redirect_count} redirecciones)`
      });
    }

    // Punycode IDN Homograph check (e.g., xn--bnco-4na.com)
    if (finalUrl.hostname.toLowerCase().includes('xn--')) {
      findings.push({
        id: generateUlid('fnd'),
        rule_code: 'PUNYCODE_HOMOGRAPH_DOMAIN',
        category: 'TRANSPORT',
        severity: 'HIGH',
        line_number: 1,
        column_number: 1,
        dom_selector: 'document:domain',
        citizen_explanation:
          'El nombre del sitio usa caracteres especiales codificados (Punycode) que suelen usarse para imitar letras de bancos o marcas reales.',
        technical_detail: `Dominio internacionalizado IDN detectado con prefijo ACE 'xn--': ${finalUrl.hostname}.`,
        code_snippet: `Host: ${finalUrl.hostname}`
      });
    }

    // Raw IP address hosting web page
    if (parseIPv4(finalUrl.hostname)) {
      findings.push({
        id: generateUlid('fnd'),
        rule_code: 'RAW_IP_HOST_PHISHING',
        category: 'TRANSPORT',
        severity: 'HIGH',
        line_number: 1,
        column_number: 1,
        dom_selector: 'document:domain',
        citizen_explanation:
          'El enlace no usa un nombre de empresa o institución, sino una dirección numérica directa (IP), muy frecuente en servidores temporales de fraude.',
        technical_detail: `El host destino utiliza una dirección IPv4 literal (${finalUrl.hostname}) sin dominio DNS institucional.`,
        code_snippet: `Host: ${finalUrl.host}`
      });
    }

    // Missing essential security headers on HTTPS
    const missingHeaders: string[] = [];
    if (audit.is_https && !audit.security_headers.strict_transport_security) {
      missingHeaders.push('Strict-Transport-Security');
    }
    if (!audit.security_headers.content_security_policy) {
      missingHeaders.push('Content-Security-Policy');
    }
    if (!audit.security_headers.x_frame_options) {
      missingHeaders.push('X-Frame-Options');
    }

    if (missingHeaders.length >= 2) {
      findings.push({
        id: generateUlid('fnd'),
        rule_code: 'MISSING_SECURITY_HEADERS',
        category: 'TRANSPORT',
        severity: 'LOW',
        line_number: 1,
        column_number: 1,
        dom_selector: 'document:headers',
        citizen_explanation:
          'Al servidor web le faltan cabeceras de blindaje recomendadas contra suplantación en marcos (Clickjacking) o inyección de contenido.',
        technical_detail: `Cabeceras HTTP de protección ausentes en la respuesta: ${missingHeaders.join(', ')}.`,
        code_snippet: `HTTP ${audit.http_status_code} | Ausentes: ${missingHeaders.join(', ')}`
      });
    }

    return findings;
  }
}
