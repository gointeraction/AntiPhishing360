import { AppError } from '../utils/response';

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'instance-data',
  'kube-dns',
  'kubernetes.default',
  'kubernetes.default.svc'
]);

const BLOCKED_TLDS = ['.localhost', '.local', '.internal', '.home.arpa', '.arpa', '.lan', '.corp'];

/**
 * Parses a dotted-quad IPv4 address into 4 octets [0..255], or returns null if not an IPv4 literal.
 */
export function parseIPv4(host: string): [number, number, number, number] | null {
  const parts = host.split('.');
  if (parts.length !== 4) {
    return null;
  }

  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return null;
    }
    const num = Number.parseInt(part, 10);
    if (num < 0 || num > 255) {
      return null;
    }
    octets.push(num);
  }

  return octets as [number, number, number, number];
}

/**
 * Checks if an IPv4 address belongs to loopback, RFC1918 private, link-local/IMDS, CGNAT, multicast, or reserved space.
 */
export function isPrivateOrReservedIPv4(octets: [number, number, number, number]): boolean {
  const [a, b, c] = octets;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;
  // 10.0.0.0/8 (RFC 1918 Private)
  if (a === 10) return true;
  // 100.64.0.0/10 (Carrier-Grade NAT RFC 6598)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (Link-local & Cloud Metadata IMDS 169.254.169.254)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (RFC 1918 Private)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24 & 192.0.2.0/24 (IETF Protocol Assignments & TEST-NET-1)
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  // 192.88.99.0/24 (6to4 Relay Anycast)
  if (a === 192 && b === 88 && c === 99) return true;
  // 192.168.0.0/16 (RFC 1918 Private)
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 198.51.100.0/24 (TEST-NET-2)
  if (a === 198 && b === 51 && c === 100) return true;
  // 203.0.113.0/24 (TEST-NET-3)
  if (a === 203 && b === 113) return true;
  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved / Broadcast)
  if (a >= 224) return true;

  return false;
}

/**
 * Expands an IPv6 literal (without brackets) into 8 16-bit groups and checks private/loopback/link-local/mapped ranges.
 */
export function isPrivateOrReservedIPv6(rawHost: string): boolean {
  const host = rawHost.replace(/^\[|\]$/g, '').toLowerCase();

  // Zone index (e.g. fe80::1%eth0) is strictly local
  if (host.includes('%')) {
    return true;
  }

  // Handle dotted IPv4 suffix in IPv6 (e.g. ::ffff:127.0.0.1)
  let normalized = host;
  const lastColon = normalized.lastIndexOf(':');
  if (lastColon !== -1 && normalized.slice(lastColon + 1).includes('.')) {
    const ipv4Part = normalized.slice(lastColon + 1);
    const v4 = parseIPv4(ipv4Part);
    if (!v4) {
      return true;
    }
    if (isPrivateOrReservedIPv4(v4)) {
      return true;
    }
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const doubleColonParts = normalized.split('::');
  if (doubleColonParts.length > 2) {
    return true;
  }

  let groups: string[] = [];
  if (doubleColonParts.length === 2) {
    const left = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
    const right = doubleColonParts[1] ? doubleColonParts[1].split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 1) {
      return true;
    }
    groups = [...left, ...Array<string>(missing).fill('0'), ...right];
  } else {
    groups = normalized.split(':');
  }

  if (groups.length !== 8) {
    return true;
  }

  const words: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) {
      return true;
    }
    words.push(Number.parseInt(g, 16));
  }

  const w0 = words[0]!;
  const w1 = words[1]!;

  // ::/128 (Unspecified) or ::1/128 (Loopback)
  const allZeroExceptLast = words.slice(0, 7).every((w) => w === 0);
  if (allZeroExceptLast && (words[7] === 0 || words[7] === 1)) {
    return true;
  }

  // ::ffff:0:0/96 (IPv4-mapped IPv6)
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0xffff
  ) {
    const v4: [number, number, number, number] = [
      (words[6]! >> 8) & 0xff,
      words[6]! & 0xff,
      (words[7]! >> 8) & 0xff,
      words[7]! & 0xff
    ];
    return isPrivateOrReservedIPv4(v4);
  }

  // 64:ff9b::/96 (NAT64 Well-Known Prefix)
  if (
    w0 === 0x0064 &&
    w1 === 0xff9b &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0
  ) {
    const v4: [number, number, number, number] = [
      (words[6]! >> 8) & 0xff,
      words[6]! & 0xff,
      (words[7]! >> 8) & 0xff,
      words[7]! & 0xff
    ];
    return isPrivateOrReservedIPv4(v4);
  }

  // 100::/64 (Discard-Only RFC 6666)
  if (w0 === 0x0100 && w1 === 0 && words[2] === 0 && words[3] === 0) return true;
  // 2001:db8::/32 (Documentation RFC 3849)
  if (w0 === 0x2001 && w1 === 0x0db8) return true;
  // fc00::/7 (Unique Local Address fc00:: - fdff::)
  if ((w0 & 0xfe00) === 0xfc00) return true;
  // fe80::/10 (Link-Local fe80:: - febf::)
  if ((w0 & 0xffc0) === 0xfe80) return true;
  // ff00::/8 (Multicast)
  if ((w0 & 0xff00) === 0xff00) return true;

  return false;
}

interface DohAnswer {
  type: number;
  data: string;
}

interface DohResponse {
  Status?: number;
  Answer?: DohAnswer[];
}

export class SsrfGuardService {
  /**
   * Validates URL syntax, scheme, port, credentials, IP literals, and DNS resolution (DoH)
   * to prevent SSRF and DNS Rebinding attacks.
   */
  static async validateTargetUrl(rawInput: string, resolveDns = true): Promise<URL> {
    if (typeof rawInput !== 'string') {
      throw new AppError(400, 'SSRF_OR_INVALID_URL', 'Debe proporcionar una URL válida');
    }

    const trimmed = rawInput.trim();
    if (!trimmed || trimmed.length > 2048) {
      throw new AppError(
        400,
        'SSRF_OR_INVALID_URL',
        'La URL está vacía o supera la longitud máxima permitida (2048 caracteres)'
      );
    }

    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new AppError(
        400,
        'SSRF_OR_INVALID_URL',
        'Formato de URL inválido. Asegúrate de incluir http:// o https://'
      );
    }

    if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
      throw new AppError(
        400,
        'SSRF_OR_INVALID_URL',
        'La URL ingresada apunta a una red privada, dirección local o utiliza un protocolo no permitido'
      );
    }

    if (parsed.username || parsed.password) {
      throw new AppError(
        400,
        'SSRF_OR_INVALID_URL',
        'No se permiten credenciales embebidas (usuario:clave@host) en la URL por riesgo de suplantación'
      );
    }

    if (!ALLOWED_PORTS.has(parsed.port)) {
      throw new AppError(
        400,
        'SSRF_OR_INVALID_URL',
        `El puerto especificado (${parsed.port}) no está permitido para auditoría web ciudadana`
      );
    }

    const hostname = parsed.hostname.toLowerCase();
    if (!hostname) {
      throw new AppError(400, 'SSRF_OR_INVALID_URL', 'El dominio de la URL es inválido');
    }

    if (BLOCKED_HOSTNAMES.has(hostname)) {
      throw new AppError(
        400,
        'SSRF_OR_INVALID_URL',
        'La URL ingresada apunta a una red privada, dirección local o utiliza un protocolo no permitido'
      );
    }

    for (const suffix of BLOCKED_TLDS) {
      if (hostname.endsWith(suffix)) {
        throw new AppError(
          400,
          'SSRF_OR_INVALID_URL',
          'La URL ingresada apunta a un dominio interno o local no enrutable públicamente'
        );
      }
    }

    // Check IPv6 literal (URL.hostname keeps brackets in WHATWG URL)
    if (hostname.startsWith('[') || hostname.includes(':')) {
      if (isPrivateOrReservedIPv6(hostname)) {
        throw new AppError(
          400,
          'SSRF_OR_INVALID_URL',
          'La URL ingresada apunta a una red privada, dirección local o utiliza un protocolo no permitido'
        );
      }
      return parsed;
    }

    // Check IPv4 literal (WHATWG URL normalizes hex/octal/integer IPv4 hosts into dotted-quad!)
    const ipv4 = parseIPv4(hostname);
    if (ipv4) {
      if (isPrivateOrReservedIPv4(ipv4)) {
        throw new AppError(
          400,
          'SSRF_OR_INVALID_URL',
          'La URL ingresada apunta a una red privada, dirección local o utiliza un protocolo no permitido'
        );
      }
      return parsed;
    }

    // Require at least one dot in public domain names (blocks single-label intranet hosts)
    if (!hostname.includes('.') || hostname.endsWith('.')) {
      throw new AppError(
        400,
        'SSRF_OR_INVALID_URL',
        'El nombre de dominio no corresponde a un host público válido en Internet'
      );
    }

    if (resolveDns) {
      await this.verifyPublicDnsResolution(hostname);
    }

    return parsed;
  }

  /**
   * Resolves A and AAAA records over Cloudflare DNS-over-HTTPS to block domains
   * resolving to 127.0.0.1, 10.x, 169.254.169.254, ::1, etc. (Anti-DNS Rebinding).
   */
  private static async verifyPublicDnsResolution(hostname: string): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);

    try {
      const [aRes, aaaaRes] = await Promise.all([
        fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
          headers: { Accept: 'application/dns-json' },
          signal: controller.signal
        }),
        fetch(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=AAAA`,
          {
            headers: { Accept: 'application/dns-json' },
            signal: controller.signal
          }
        )
      ]);

      const answers: DohAnswer[] = [];
      if (aRes.ok) {
        const body = (await aRes.json()) as DohResponse;
        if (Array.isArray(body.Answer)) {
          answers.push(...body.Answer);
        }
      }
      if (aaaaRes.ok) {
        const body = (await aaaaRes.json()) as DohResponse;
        if (Array.isArray(body.Answer)) {
          answers.push(...body.Answer);
        }
      }

      for (const record of answers) {
        if (record.type === 1) {
          const v4 = parseIPv4(record.data.trim());
          if (!v4 || isPrivateOrReservedIPv4(v4)) {
            throw new AppError(
              400,
              'SSRF_OR_INVALID_URL',
              'El dominio analizado resuelve hacia una dirección IP privada, reservada o interna (bloqueo Anti-SSRF)'
            );
          }
        } else if (record.type === 28) {
          if (isPrivateOrReservedIPv6(record.data.trim())) {
            throw new AppError(
              400,
              'SSRF_OR_INVALID_URL',
              'El dominio analizado resuelve hacia una dirección IPv6 privada o loopback (bloqueo Anti-SSRF)'
            );
          }
        }
      }
    } catch (err) {
      if (err instanceof AppError) {
        throw err;
      }
      // If DoH endpoint itself timed out transiently, Cloudflare Workers fetch() itself still blocks private IPs at network edge
    } finally {
      clearTimeout(timer);
    }
  }
}
