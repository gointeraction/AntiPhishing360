import type {
  LinkFunctionalityAuditDTO,
  ScanFindingDTO,
  TransportAuditResult,
} from '../types.ts';
import { CryptoService } from './crypto.service.ts';
import { SsrfGuardService } from './ssrf-guard.service.ts';
import { TransportService } from './transport.service.ts';
import { AntiphishingCtiService } from './url-heuristics.service.ts';

const FREE_EPHEMERAL_HOSTS = [
  '.vercel.app',
  '.netlify.app',
  '.pages.dev',
  '.web.app',
  '.firebaseapp.com',
  '.github.io',
  '.workers.dev',
  '.onrender.com',
  '.glitch.me',
  '.000webhostapp.com',
  '.weebly.com',
  '.wixsite.com',
  '.blogspot.com',
  '.surge.sh',
  '.ngrok-free.app',
  '.ngrok.io',
  '.trycloudflare.com',
  '.duckdns.org',
  '.rf.gd',
  '.epizy.com',
  '.infinityfreeapp.com',
  '.replit.app',
  '.railway.app',
  '.fly.dev',
  '.my.canva.site',
  'sites.google.com',
  'forms.gle',
  '.ejemplo.app',
];

const URL_SHORTENER_HOSTS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'cutt.ly',
  'is.gd',
  'rebrand.ly',
  'rb.gy',
  'shorturl.at',
  'qrco.de',
  'ow.ly',
  'buff.ly',
  'v.gd',
  'clck.ru',
]);

const EXFILTRATION_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  {
    label: 'Telegram Bot API (Exfiltración Directa)',
    regex: /https?:\/\/api\.telegram\.org\/bot[0-9]{6,12}:[A-Za-z0-9_-]{20,}/i,
  },
  {
    label: 'Discord Webhook (Robo de Credenciales)',
    regex: /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/i,
  },
  {
    label: 'Servicio de Reenvío de Formularios (Formspree / Getform / Web3Forms / EmailJS)',
    regex: /https?:\/\/(?:formspree\.io\/f\/|getform\.io\/f\/|api\.web3forms\.com\/submit|api\.emailjs\.com\/api\/v1\.0\/email\/send|webhook\.site\/)/i,
  },
  {
    label: 'Google Apps Script Collector',
    regex: /https?:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec/i,
  },
  {
    label: 'Receptor PHP de Phishing (correo/post/token/otp.php)',
    regex: /(?:https?:\/\/[^\s"'<>]+|\/[A-Za-z0-9_/-]*)\/(?:post|send|correo|enviar|procesar|validacion|validar|paso2|token|otp|captura|guardar|log)\.php\b/i,
  },
];

export interface LinkFunctionalityProbeOutput {
  effectiveTransport: TransportAuditResult;
  audit: LinkFunctionalityAuditDTO;
  findings: ScanFindingDTO[];
  combinedBundleCorpus: string;
}

export class LinkFunctionalityService {
  static isFreeOrEphemeralHosting(hostname: string, fullUrl?: string): boolean {
    const h = hostname.toLowerCase().trim();
    if (h === 'docs.google.com' && fullUrl && /\/forms\//i.test(fullUrl)) {
      return true;
    }
    return FREE_EPHEMERAL_HOSTS.some((suffix) =>
      suffix.startsWith('.') ? h.endsWith(suffix) : h === suffix || h.endsWith(`.${suffix}`)
    );
  }

  static isUrlShortener(hostname: string): boolean {
    const h = hostname.toLowerCase().replace(/^www\./, '');
    return URL_SHORTENER_HOSTS.has(h);
  }

  /**
   * Ejecuta una conexión activa de verificación funcional sobre el enlace:
   * 1. Desenmascara redirecciones ocultas en HTML/JS (<meta refresh>, window.location) haciendo nueva conexión.
   * 2. Descarga e inspecciona bundles JS externos (<script src="...">) en aplicaciones SPA (React/Vite/Vue/Next).
   * 3. Detecta canales activos de exfiltración (Telegram Bot API, Discord Webhooks, PHP mailers, Formspree).
   * 4. Verifica si formularios de claves/banca están activos sobre alojamientos gratuitos/efímeros.
   */
  static async verifyAndInspect(params: {
    initialUrl: string;
    transport: TransportAuditResult | null;
    unreachableReason?: string;
    deviceProfile?: string;
  }): Promise<LinkFunctionalityProbeOutput> {
    const findings: ScanFindingDTO[] = [];
    let initialHost = '';
    try {
      initialHost = new URL(params.initialUrl).hostname.toLowerCase();
    } catch {
      initialHost = '';
    }

    // Case 1: Target server did not respond (offline, sinkholed, DNS NXDOMAIN or takedown)
    if (!params.transport) {
      const fallbackUrl = params.initialUrl;
      let parsed: URL;
      try {
        parsed = new URL(fallbackUrl);
      } catch {
        parsed = new URL('http://enlace-invalido.ejemplo');
      }
      const isHttps = parsed.protocol === 'https:';
      const offlineTransport: TransportAuditResult = {
        finalUrl: parsed.toString(),
        targetDomain: parsed.hostname.toLowerCase(),
        protocol: isHttps ? 'https' : 'http',
        isHttps,
        httpStatusCode: 0,
        redirectCount: 0,
        responseTimeMs: 0,
        contentType: 'unreachable',
        redirectChain: [parsed.toString()],
        securityHeaders: {
          strict_transport_security: false,
          content_security_policy: false,
          x_frame_options: false,
        },
        htmlContent: [
          `<!-- Verificación Funcional Detector360: El servidor (${parsed.hostname}) no respondió a la conexión en vivo -->`,
          `<!-- Motivo técnico: ${params.unreachableReason || 'Servidor apagado, dado de baja o bloqueado por DNS'} -->`,
        ].join('\n'),
        simulatedDemo: true,
      };

      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'LINK_INACTIVE_OR_EVASIVE_HOST',
        category: 'TRANSPORT',
        severity: 'MEDIUM',
        line_number: 1,
        column_number: 1,
        dom_selector: 'connection:probe',
        citizen_explanation:
          'Al probar la funcionalidad del enlace en tiempo real, el servidor no respondió (muchas estafas apagan su página horas después o bloquean países/revisiones).',
        technical_detail: `Fallo de conexión TCP/TLS/HTTP durante verificación funcional activa hacia ${parsed.hostname}.`,
        code_snippet: `Probe GET ${parsed.toString()} -> TIMEOUT / NXDOMAIN / CONNECTION_REFUSED`,
      });

      return {
        effectiveTransport: offlineTransport,
        audit: {
          checked_live: true,
          reachable: false,
          is_functional: false,
          functionality_status: 'INACTIVE_OR_TAKEDOWN',
          http_status_code: 0,
          response_time_ms: 0,
          content_type: 'unreachable',
          initial_url: params.initialUrl,
          resolved_final_url: parsed.toString(),
          redirect_hops: 0,
          redirect_chain: [parsed.toString()],
          client_redirect_detected: false,
          client_redirect_target: null,
          spa_bundles_inspected: 0,
          login_or_financial_form_active: false,
          exfiltration_endpoints: [],
          summary:
            'Enlace inactivo o inaccesible: el servidor remoto no respondió a la conexión en vivo (posible baja por denuncia, dominio recién creado sin activar o evasión geográfica).',
        },
        findings,
        combinedBundleCorpus: '',
      };
    }

    let effectiveTransport = params.transport;
    let clientRedirectDetected = false;
    let clientRedirectTarget: string | null = null;

    // Step 1: Detect & follow client-side <meta http-equiv="refresh"> or JS window.location redirect
    const clientTarget = this.extractClientSideRedirect(
      effectiveTransport.htmlContent,
      effectiveTransport.finalUrl
    );

    if (clientTarget && clientTarget !== effectiveTransport.finalUrl) {
      try {
        const validatedClientUrl = SsrfGuardService.validatePublicUrl(clientTarget);
        clientRedirectDetected = true;
        clientRedirectTarget = validatedClientUrl.toString();

        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'CLOAKED_CLIENT_SIDE_REDIRECT',
          category: 'JS_SCRIPT',
          severity: 'HIGH',
          line_number: 1,
          column_number: 1,
          dom_selector: 'document:client-redirect',
          citizen_explanation: `Este enlace funciona como un trampolín oculto: apenas lo abres te desvía automáticamente hacia otra dirección (${validatedClientUrl.hostname}).`,
          technical_detail: `Redirección del lado del cliente detectada (meta-refresh / window.location) apuntando a ${validatedClientUrl.toString()}.`,
          code_snippet: `${effectiveTransport.finalUrl} ==> ${validatedClientUrl.toString()}`,
        });

        const redirectedTransport = await TransportService.fetchAndAudit(
          validatedClientUrl.toString(),
          params.deviceProfile || 'android'
        );
        const mergedChain = [
          ...(effectiveTransport.redirectChain || [params.initialUrl]),
          ...(redirectedTransport.redirectChain || [validatedClientUrl.toString()]),
        ];
        effectiveTransport = {
          ...redirectedTransport,
          redirectCount: effectiveTransport.redirectCount + redirectedTransport.redirectCount + 1,
          redirectChain: Array.from(new Set(mergedChain)),
        };
      } catch {
        // Keep initial transport if secondary hop fails
      }
    }

    // Step 2: URL Shortener check
    if (initialHost && this.isUrlShortener(initialHost)) {
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'URL_SHORTENER_REDIRECT_MASK',
        category: 'TRANSPORT',
        severity: effectiveTransport.targetDomain !== initialHost ? 'MEDIUM' : 'LOW',
        line_number: 1,
        column_number: 1,
        dom_selector: 'connection:shortener',
        citizen_explanation: `El enlace usa un acortador (${initialHost}) para esconder la verdadera dirección a la que llegarás (${effectiveTransport.targetDomain}). Los bancos nunca envían enlaces acortados para pedir claves.`,
        technical_detail: `Acortador de URL desenmascarado: ${params.initialUrl} -> ${effectiveTransport.finalUrl}`,
        code_snippet: `${initialHost} -> ${effectiveTransport.targetDomain}`,
      });
    }

    // Step 3: Fetch & inspect external SPA JavaScript bundles (<script src="...">) on non-official domains
    const isOfficialHost = AntiphishingCtiService.isOfficialWhitelistedDomain(
      effectiveTransport.targetDomain
    );
    let spaBundlesInspected = 0;
    const bundleChunks: string[] = [];

    if (!isOfficialHost && !effectiveTransport.simulatedDemo) {
      const scriptUrls = this.extractInspectableScriptUrls(
        effectiveTransport.htmlContent,
        effectiveTransport.finalUrl
      );
      for (const scriptUrl of scriptUrls.slice(0, 2)) {
        const jsText = await this.fetchScriptBundleSafe(scriptUrl);
        if (jsText) {
          spaBundlesInspected++;
          bundleChunks.push(jsText);
        }
      }
    }

    const combinedBundleCorpus = bundleChunks.join('\n');
    const fullCorpus = `${effectiveTransport.htmlContent}\n${combinedBundleCorpus}`;

    // Step 4: Detect active credential / financial forms in HTML or SPA JS bundles
    const hasHtmlPasswordOrCard =
      /<input\b[^>]*type\s*=\s*["']?password["']?/i.test(effectiveTransport.htmlContent) ||
      /\b(clave|contrase[ñn]a|password|pin_cajero|cvv|tarjeta|cedula|token|coordenadas|usuario)\b/i.test(
        this.extractFormAndInputAttributes(effectiveTransport.htmlContent)
      );

    const hasSpaCredentialTrap =
      combinedBundleCorpus.length > 0 &&
      /type\s*:\s*["']password["']|type=["']password["']/i.test(combinedBundleCorpus) &&
      /\b(clave|contrase|usuario|cedula|banesco|venezuela|mercantil|provincial|bancamiga|patria|token|otp|tarjeta|cvv)\b/i.test(
        combinedBundleCorpus
      );

    const loginOrFinancialActive = hasHtmlPasswordOrCard || hasSpaCredentialTrap;

    if (!isOfficialHost && hasSpaCredentialTrap) {
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'SPA_HIDDEN_CREDENTIAL_HARVESTER',
        category: 'JS_SCRIPT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'script[src]:spa-bundle',
        citizen_explanation:
          'Al inspeccionar la funcionalidad interna del enlace, descubrimos un formulario oculto dentro de programas JavaScript diseñado para pedir claves o datos bancarios.',
        technical_detail: `Formulario dinámico de captura de credenciales detectado dentro de ${spaBundlesInspected} bundle(s) JS externos en dominio no oficial (${effectiveTransport.targetDomain}).`,
        code_snippet: `SPA Bundle (${effectiveTransport.targetDomain}) -> input[type="password"] + campos bancarios`,
      });
    }

    // Step 5: Detect active exfiltration channels (Telegram bots, Discord webhooks, PHP mailers, cross-domain forms)
    const exfiltrationEndpoints: string[] = [];
    for (const pattern of EXFILTRATION_PATTERNS) {
      const m = pattern.regex.exec(fullCorpus);
      if (m && !isOfficialHost) {
        const matchedEndpoint = m[0].slice(0, 140);
        exfiltrationEndpoints.push(`${pattern.label}: ${matchedEndpoint}`);
      }
    }

    if (exfiltrationEndpoints.length > 0) {
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'TELEGRAM_OR_WEBHOOK_EXFILTRATION',
        category: 'JS_SCRIPT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'network:exfiltration-webhook',
        citizen_explanation:
          '¡Peligro confirmado! Conectamos con el código del enlace y descubrimos que envía directamente lo que escribas hacia un chat de Telegram, Discord o buzón pirata de estafadores.',
        technical_detail: `Canal activo de exfiltración de credenciales detectado: ${exfiltrationEndpoints.join(' | ')}`,
        code_snippet: exfiltrationEndpoints[0].slice(0, 240),
      });
    }

    // Step 6: Free / Ephemeral Cloud Hosting + Credential Form = Phishing Kit!
    const isFreeHosting = this.isFreeOrEphemeralHosting(
      effectiveTransport.targetDomain,
      effectiveTransport.finalUrl
    );
    if (!isOfficialHost && isFreeHosting && loginOrFinancialActive) {
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'FREE_HOSTING_CREDENTIAL_PHISHING',
        category: 'TRANSPORT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'connection:ephemeral-hosting',
        citizen_explanation: `Esta página pide contraseñas o datos sensibles desde un alojamiento web gratuito (${effectiveTransport.targetDomain}). Ningún banco ni institución oficial aloja su banca en línea en servidores gratuitos.`,
        technical_detail: `Captura activa de credenciales sobre plataforma de hosting gratuito/efímero (${effectiveTransport.targetDomain}).`,
        code_snippet: `Host efímero: ${effectiveTransport.finalUrl}`,
      });
    }

    // Determine functionality status & human-readable summary
    const statusCode = effectiveTransport.httpStatusCode || 200;
    const isHttpFunctional = statusCode >= 200 && statusCode < 400;
    const isWafBlocked = statusCode === 403 || statusCode === 429 || statusCode === 503;

    let functionalityStatus: LinkFunctionalityAuditDTO['functionality_status'] =
      'ONLINE_FUNCTIONAL';
    if (clientRedirectDetected) {
      functionalityStatus = 'CLOAKED_CLIENT_REDIRECT';
    } else if (effectiveTransport.redirectCount > 0) {
      functionalityStatus = 'REDIRECT_UNMASKED';
    } else if (isWafBlocked) {
      functionalityStatus = 'BOT_WAF_PROTECTED';
    } else if (!isHttpFunctional) {
      functionalityStatus = 'INACTIVE_OR_TAKEDOWN';
    }

    const latencyMs = effectiveTransport.responseTimeMs ?? 48;
    const chain = effectiveTransport.redirectChain || [
      params.initialUrl,
      ...(effectiveTransport.finalUrl !== params.initialUrl ? [effectiveTransport.finalUrl] : []),
    ];

    let summary = `Enlace activo y funcional (HTTP ${statusCode} en ${latencyMs} ms).`;
    if (functionalityStatus === 'CLOAKED_CLIENT_REDIRECT') {
      summary = `Enlace activo con desvío oculto: redirige automáticamente hacia ${effectiveTransport.targetDomain} (HTTP ${statusCode}).`;
    } else if (functionalityStatus === 'REDIRECT_UNMASKED') {
      summary = `Enlace activo con ${effectiveTransport.redirectCount} redirección(es) hasta llegar a ${effectiveTransport.targetDomain} (HTTP ${statusCode} en ${latencyMs} ms).`;
    } else if (functionalityStatus === 'BOT_WAF_PROTECTED') {
      summary = `Servidor en línea protegido por cortafuegos anti-bots (HTTP ${statusCode} en ${latencyMs} ms).`;
    } else if (functionalityStatus === 'INACTIVE_OR_TAKEDOWN') {
      summary = `El enlace devolvió estado de error o página dada de baja (HTTP ${statusCode}).`;
    }

    if (exfiltrationEndpoints.length > 0) {
      summary += ' Se detectó envío activo de datos hacia canales externos de captura.';
    } else if (loginOrFinancialActive && !isOfficialHost) {
      summary += ' Mantiene activo un formulario de solicitud de credenciales.';
    }

    return {
      effectiveTransport,
      audit: {
        checked_live: true,
        reachable: statusCode > 0,
        is_functional: isHttpFunctional,
        functionality_status: functionalityStatus,
        http_status_code: statusCode,
        response_time_ms: latencyMs,
        content_type: effectiveTransport.contentType || 'text/html',
        initial_url: params.initialUrl,
        resolved_final_url: effectiveTransport.finalUrl,
        redirect_hops: effectiveTransport.redirectCount,
        redirect_chain: chain,
        client_redirect_detected: clientRedirectDetected,
        client_redirect_target: clientRedirectTarget,
        spa_bundles_inspected: spaBundlesInspected,
        login_or_financial_form_active: loginOrFinancialActive,
        exfiltration_endpoints: exfiltrationEndpoints,
        summary,
      },
      findings,
      combinedBundleCorpus,
    };
  }

  private static extractClientSideRedirect(html: string, baseUrl: string): string | null {
    if (!html || html.length > 24000) return null;

    // 1. <meta http-equiv="refresh" content="0; url=https://...">
    const metaMatch = html.match(
      /<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"'\s>]+)["']/i
    );
    if (metaMatch && metaMatch[1]) {
      try {
        return new URL(metaMatch[1].trim(), baseUrl).toString();
      } catch {
        // ignore
      }
    }

    // 2. Thin JS redirector page (body has no meaningful content, just window.location = "...")
    const strippedText = html
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/<style[\s\S]*?<\/style>/gi, '')
      .replace(/<[^>]+>/g, '')
      .trim();

    if (strippedText.length < 220) {
      const jsLocMatch = html.match(
        /(?:window\.)?location(?:\.href|\s*\.\s*replace|\s*\.\s*assign)?\s*(?:=|\()\s*["'](https?:\/\/[^"'\s)]+)["']/i
      );
      if (jsLocMatch && jsLocMatch[1]) {
        try {
          return new URL(jsLocMatch[1].trim(), baseUrl).toString();
        } catch {
          return null;
        }
      }
    }

    return null;
  }

  private static extractInspectableScriptUrls(html: string, baseUrl: string): string[] {
    const urls: string[] = [];
    const regex = /<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))[^>]*>/gi;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(html)) !== null) {
      const rawSrc = (m[1] || m[2] || m[3] || '').trim();
      if (!rawSrc || rawSrc.startsWith('data:')) continue;
      // Skip well-known benign analytics/CDN libraries to focus budget on app bundles
      if (
        /(googletagmanager|google-analytics|gtag|cloudflareinsights|jquery|bootstrap|fontawesome|unpkg\.com\/lucide)/i.test(
          rawSrc
        )
      ) {
        continue;
      }
      try {
        const resolved = new URL(rawSrc, baseUrl);
        SsrfGuardService.validatePublicUrl(resolved.toString());
        urls.push(resolved.toString());
      } catch {
        // ignore invalid or private script URLs
      }
    }
    return urls;
  }

  private static async fetchScriptBundleSafe(scriptUrl: string): Promise<string | null> {
    try {
      const res = await fetch(scriptUrl, {
        method: 'GET',
        signal: AbortSignal.timeout(2500),
        headers: {
          Accept: 'application/javascript,text/javascript,*/*;q=0.8',
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
        },
      });
      if (!res.ok || !res.body) return null;
      const buf = await res.arrayBuffer();
      const slice = buf.byteLength > 184320 ? buf.slice(0, 184320) : buf;
      return new TextDecoder('utf-8', { fatal: false }).decode(slice);
    } catch {
      return null;
    }
  }

  private static extractFormAndInputAttributes(html: string): string {
    const chunks: string[] = [];
    const re = /<(?:input|form|button|label)\b[^>]*>/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      chunks.push(m[0]);
    }
    return chunks.join(' ');
  }
}
