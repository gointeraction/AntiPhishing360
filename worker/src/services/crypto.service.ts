const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PBKDF2_ITERATIONS = 210_000;

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : '0' + hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function base64UrlEncode(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(input: string): Uint8Array {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export class CryptoService {
  static generateUlid(prefix?: string): string {
    let time = Date.now();
    let timeChars = '';
    for (let i = 0; i < 10; i++) {
      const mod = time % 32;
      timeChars = CROCKFORD_ALPHABET[mod] + timeChars;
      time = Math.floor(time / 32);
    }

    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    let randChars = '';
    for (let i = 0; i < 16; i++) {
      randChars += CROCKFORD_ALPHABET[randomBytes[i] & 31];
    }

    const ulid = `${timeChars}${randChars}`;
    return prefix ? `${prefix}_${ulid}` : ulid;
  }

  static async sha256Hex(payload: string): Promise<string> {
    const encoded = new TextEncoder().encode(payload);
    const digest = await crypto.subtle.digest('SHA-256', encoded);
    return bytesToHex(new Uint8Array(digest));
  }

  static async hashPassword(password: string): Promise<string> {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-512',
      },
      keyMaterial,
      512
    );

    const hashHex = bytesToHex(new Uint8Array(derivedBits));
    const saltHex = bytesToHex(salt);
    return `pbkdf2_sha512$${PBKDF2_ITERATIONS}$${saltHex}$${hashHex}`;
  }

  static async verifyPassword(password: string, storedHash: string): Promise<boolean> {
    const parts = storedHash.split('$');
    if (parts.length !== 4 || parts[0] !== 'pbkdf2_sha512') {
      return false;
    }
    const iterations = parseInt(parts[1], 10);
    if (!Number.isFinite(iterations) || iterations < 10_000) {
      return false;
    }
    const salt = hexToBytes(parts[2]);
    const expectedHash = hexToBytes(parts[3]);
    if (expectedHash.length !== 64) {
      return false;
    }

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations,
        hash: 'SHA-512',
      },
      keyMaterial,
      512
    );

    return constantTimeEqual(new Uint8Array(derivedBits), expectedHash);
  }

  static generateRandomToken(byteLength = 32): string {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return base64UrlEncode(bytes);
  }

  static async signJwt(
    payload: Record<string, unknown>,
    secret: string,
    expiresInSeconds = 900
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'HS256', typ: 'JWT' };
    const fullPayload = {
      ...payload,
      iat: now,
      exp: now + expiresInSeconds,
    };

    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(signingInput)
    );

    return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
  }

  static async verifyJwt<T = Record<string, unknown>>(
    token: string,
    secret: string
  ): Promise<T | null> {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const [encodedHeader, encodedPayload, encodedSig] = parts;
      const signingInput = `${encodedHeader}.${encodedPayload}`;

      const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      );

      const sigBytes = base64UrlDecode(encodedSig);
      const valid = await crypto.subtle.verify(
        'HMAC',
        key,
        sigBytes as BufferSource,
        new TextEncoder().encode(signingInput)
      );

      if (!valid) return null;

      const payloadJson = new TextDecoder().decode(base64UrlDecode(encodedPayload));
      const payload = JSON.parse(payloadJson) as Record<string, unknown>;
      const now = Math.floor(Date.now() / 1000);

      if (typeof payload.exp === 'number' && payload.exp < now) {
        return null;
      }

      return payload as T;
    } catch {
      return null;
    }
  }
}
