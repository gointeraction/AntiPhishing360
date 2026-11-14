export class SsrfViolationError extends Error {
  public readonly code = 'INVALID_OR_RESTRICTED_URL';
  constructor(message: string) {
    super(message);
    this.name = 'SsrfViolationError';
  }
}

export class SsrfGuardService {
  private static readonly ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);

  static validatePublicUrl(rawUrl: string): URL {
    if (!rawUrl || typeof rawUrl !== 'string') {
      throw new SsrfViolationError(
        'Por favor ingresa una dirección web pública válida que comience por http:// o https://'
      );
    }

    const trimmed = rawUrl.trim();
    if (trimmed.length > 2048) {
      throw new SsrfViolationError('La dirección web ingresada es demasiado larga.');
    }

    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new SsrfViolationError(
        'Por favor ingresa una dirección web pública válida que comience por http:// o https://'
      );
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new SsrfViolationError(
        'Por seguridad solo se analizan enlaces web que comiencen por http:// o https://'
      );
    }

    if (parsed.username || parsed.password) {
      throw new SsrfViolationError(
        'No se permiten credenciales incrustadas dentro de la dirección web.'
      );
    }

    if (!this.ALLOWED_PORTS.has(parsed.port)) {
      throw new SsrfViolationError(
        'El puerto indicado en el enlace está restringido por políticas de seguridad.'
      );
    }

    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
    if (!hostname || hostname.length < 3) {
      throw new SsrfViolationError('El dominio ingresado no es válido.');
    }

    if (this.isRestrictedHostname(hostname)) {
      throw new SsrfViolationError(
        'Por favor ingresa una dirección web pública válida que comience por http:// o https://'
      );
    }

    return parsed;
  }

  private static isRestrictedHostname(hostname: string): boolean {
    const blockedExact = new Set([
      'localhost',
      'ip6-localhost',
      'ip6-loopback',
      'metadata.google.internal',
      'metadata',
      'instance-data',
      '0.0.0.0',
    ]);

    if (blockedExact.has(hostname)) return true;

    if (
      hostname.endsWith('.localhost') ||
      hostname.endsWith('.local') ||
      hostname.endsWith('.internal') ||
      hostname.endsWith('.arpa') ||
      hostname.endsWith('.home') ||
      hostname.endsWith('.lan')
    ) {
      return true;
    }

    // IPv6 literal check (URL.hostname wraps IPv6 in brackets: [::1])
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      const ipv6 = hostname.slice(1, -1).toLowerCase();
      return this.isPrivateIpv6(ipv6);
    }

    // Numeric / octal / hex IPv4 bypass attempts (e.g. 2130706433 or 0x7f000001)
    if (/^(0x[0-9a-f]+|\d+)$/i.test(hostname)) {
      return true;
    }

    // Standard dotted IPv4 check
    const ipv4Match = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4Match) {
      const octets = ipv4Match.slice(1, 5).map((n) => parseInt(n, 10));
      if (octets.some((o) => o < 0 || o > 255)) return true;
      return this.isPrivateIpv4(octets[0], octets[1], octets[2], octets[3]);
    }

    // Must contain at least one dot for a public FQDN
    if (!hostname.includes('.')) {
      return true;
    }

    return false;
  }

  private static isPrivateIpv4(a: number, b: number, _c: number, _d: number): boolean {
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / AWS metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmark
    if (a >= 224) return true; // Multicast & Reserved
    return false;
  }

  private static isPrivateIpv6(ipv6: string): boolean {
    if (ipv6 === '::1' || ipv6 === '::' || ipv6 === '0:0:0:0:0:0:0:1' || ipv6 === '0:0:0:0:0:0:0:0') {
      return true;
    }
    // Unique local fc00::/7 (fc.. or fd..)
    if (ipv6.startsWith('fc') || ipv6.startsWith('fd')) {
      return true;
    }
    // Link-local fe80::/10
    if (/^fe[89ab]/.test(ipv6)) {
      return true;
    }
    // IPv4-mapped IPv6 ::ffff:x.x.x.x
    if (ipv6.includes('ffff:')) {
      return true;
    }
    return false;
  }
}
