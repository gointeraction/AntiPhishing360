const CROCKFORD_BASE32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * Generates a lexicographically sortable, cryptographically random ULID
 * with a domain entity prefix (e.g. usr_, scn_, fnd_, rtk_, alt_).
 */
export function generateUlid(prefix?: string): string {
  const now = Date.now();
  let timePart = '';
  let time = now;

  for (let i = 0; i < 10; i++) {
    const mod = time % 32;
    timePart = CROCKFORD_BASE32[mod]! + timePart;
    time = Math.floor(time / 32);
  }

  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);

  let randomPart = '';
  for (let i = 0; i < 16; i++) {
    randomPart += CROCKFORD_BASE32[randomBytes[i]! & 31]!;
  }

  const rawUlid = `${timePart}${randomPart}`;
  return prefix ? `${prefix}_${rawUlid}` : rawUlid;
}
