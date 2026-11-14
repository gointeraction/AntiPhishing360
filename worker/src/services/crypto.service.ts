import { JwtAccessPayload } from '../types/models';

const PBKDF2_ITERATIONS = 210_000;
const SALT_BYTES = 16;
const KEY_BITS = 512;
const HASH_PREFIX = 'pbkdf2-sha512';
const JWT_ISSUER = 'detector360-edge';

const encoder = new TextEncoder();

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const parsed = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(parsed)) {
      throw new Error('Invalid hex character');
    }
    bytes[i] = parsed;
  }
  return bytes;
}

function base64UrlEncode(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Constant-time byte array comparison to prevent timing side-channel attacks.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

export class CryptoService {
  /**
   * Hashes a plaintext password using PBKDF2-HMAC-SHA512 (210,000 iterations)
   * Output format: $pbkdf2-sha512$210000$<salt_hex>$<hash_hex>
   */
  static async hashPassword(password: string): Promise<string> {
    const salt = new Uint8Array(SALT_BYTES);
    crypto.getRandomValues(salt);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-512'
      },
      keyMaterial,
      KEY_BITS
    );

    const hashBytes = new Uint8Array(derivedBits);
    return `$${HASH_PREFIX}$${PBKDF2_ITERATIONS}$${bytesToHex(salt)}$${bytesToHex(hashBytes)}`;
  }

  /**
   * Verifies a plaintext password against a stored PBKDF2-HMAC-SHA512 hash in constant time.
   */
  static async verifyPassword(password: string, storedHash: string): Promise<boolean> {
    try {
      const parts = storedHash.split('$').filter(Boolean);
      if (parts.length !== 4 || parts[0] !== HASH_PREFIX) {
        return false;
      }

      const iterations = Number.parseInt(parts[1]!, 10);
      if (!Number.isFinite(iterations) || iterations < 100_000 || iterations > 1_000_000) {
        return false;
      }

      const salt = hexToBytes(parts[2]!);
      const expectedHash = hexToBytes(parts[3]!);

      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
      );

      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt,
          iterations,
          hash: 'SHA-512'
        },
        keyMaterial,
        expectedHash.length * 8
      );

      return timingSafeEqual(new Uint8Array(derivedBits), expectedHash);
    } catch {
      return false;
    }
  }

  /**
   * Generates a SHA-256 hex digest for arbitrary strings (URL cache keys, refresh token hashes, forensic integrity).
   */
  static async sha256Hex(input: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
    return bytesToHex(new Uint8Array(digest));
  }

  /**
   * Generates a cryptographically strong opaque refresh token (32 bytes -> base64url).
   */
  static generateOpaqueToken(byteLength = 32): string {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return base64UrlEncode(bytes);
  }

  /**
   * Signs an HS256 JWT Access Token (default TTL: 900 seconds = 15 minutes).
   */
  static async signAccessToken(
    user: { id: string; alias: string; email: string },
    secret: string,
    ttlSeconds = 900
  ): Promise<string> {
    if (!secret || secret.length < 32) {
      throw new Error('JWT_SECRET lacks minimum cryptographic length');
    }

    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload: JwtAccessPayload = {
      sub: user.id,
      alias: user.alias,
      email: user.email,
      iat: now,
      exp: now + ttlSeconds,
      iss: JWT_ISSUER,
      type: 'access'
    };

    const encodedHeader = base64UrlEncode(encoder.encode(JSON.stringify(header)));
    const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const hmacKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(signingInput));
    return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
  }

  /**
   * Verifies an HS256 JWT Access Token signature, issuer, type, and expiration.
   */
  static async verifyAccessToken(token: string, secret: string): Promise<JwtAccessPayload | null> {
    try {
      if (!secret || secret.length < 32) {
        return null;
      }

      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }

      const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
      const headerJson = JSON.parse(new TextDecoder().decode(base64UrlDecode(encodedHeader))) as {
        alg?: string;
        typ?: string;
      };

      if (headerJson.alg !== 'HS256' || headerJson.typ !== 'JWT') {
        return null;
      }

      const hmacKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      );

      const signingInput = `${encodedHeader}.${encodedPayload}`;
      const signatureBytes = base64UrlDecode(encodedSignature);

      const isValid = await crypto.subtle.verify(
        'HMAC',
        hmacKey,
        signatureBytes,
        encoder.encode(signingInput)
      );

      if (!isValid) {
        return null;
      }

      const payload = JSON.parse(
        new TextDecoder().decode(base64UrlDecode(encodedPayload))
      ) as JwtAccessPayload;

      const now = Math.floor(Date.now() / 1000);
      if (
        payload.type !== 'access' ||
        payload.iss !== JWT_ISSUER ||
        typeof payload.sub !== 'string' ||
        typeof payload.exp !== 'number' ||
        payload.exp <= now
      ) {
        return null;
      }

      return payload;
    } catch {
      return null;
    }
  }
}
