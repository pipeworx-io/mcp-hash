interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * Cryptographic hash & HMAC MCP.
 *
 * Keyless, offline: compute MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 digests
 * and HMACs of text. SHA & HMAC use the platform WebCrypto (crypto.subtle);
 * MD5 is a small inlined implementation. No API, no key, no data leaves the
 * process. (MD5/SHA-1 are legacy — fine for checksums/ETags, not for security.)
 */


const SUBTLE: Record<string, string> = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Inlined MD5 (RFC 1321) over UTF-8 bytes.
function md5(text: string): string {
  const input = new TextEncoder().encode(text);
  const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const ml = input.length * 8;
  const buf = new Uint8Array((((input.length + 8) >> 6) + 1) * 64);
  buf.set(input); buf[input.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(buf.length - 8, ml >>> 0, true);
  dv.setUint32(buf.length - 4, Math.floor(ml / 4294967296) >>> 0, true);
  const rol = (x: number, c: number) => (x << c) | (x >>> (32 - c));
  for (let off = 0; off < buf.length; off += 64) {
    const M = new Uint32Array(16);
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B; B = (B + rol(F, s[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const le = (n: number) => { let h = ''; for (let i = 0; i < 4; i++) h += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0'); return h; };
  return le(a0) + le(b0) + le(c0) + le(d0);
}

const tools: McpToolExport['tools'] = [
  {
    name: 'hash',
    description: 'Compute a cryptographic hash (hex digest) of text: algorithm = md5, sha1, sha256 (default), sha384, or sha512. Keyless/offline; the input is not stored or transmitted. MD5/SHA-1 are legacy (checksums only, not security).',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The text to hash (UTF-8).' },
        algorithm: { type: 'string', description: 'md5 | sha1 | sha256 (default) | sha384 | sha512.' },
      },
      required: ['text'],
    },
  },
  {
    name: 'hmac',
    description: 'Compute an HMAC (hex) of text with a secret key. algorithm = sha1, sha256 (default), sha384, or sha512. Keyless/offline.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The message to authenticate.' },
        key: { type: 'string', description: 'The secret key.' },
        algorithm: { type: 'string', description: 'sha1 | sha256 (default) | sha384 | sha512.' },
      },
      required: ['text', 'key'],
    },
  },
];

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  switch (name) {
    case 'hash': {
      const text = reqStr(args, 'text', '"hello"');
      const algo = (typeof args.algorithm === 'string' ? args.algorithm : 'sha256').toLowerCase();
      if (algo === 'md5') return { algorithm: 'md5', hex: md5(text), bits: 128 };
      if (!SUBTLE[algo]) return { error: `Unknown algorithm "${algo}". Use md5, sha1, sha256, sha384 or sha512.` };
      const buf = await crypto.subtle.digest(SUBTLE[algo], new TextEncoder().encode(text));
      return { algorithm: algo, hex: toHex(buf), bits: buf.byteLength * 8 };
    }
    case 'hmac': {
      const text = reqStr(args, 'text', '"hello"');
      const keyStr = reqStr(args, 'key', '"secret"');
      const algo = (typeof args.algorithm === 'string' ? args.algorithm : 'sha256').toLowerCase();
      if (!SUBTLE[algo]) return { error: `Unknown algorithm "${algo}". Use sha1, sha256, sha384 or sha512.` };
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(keyStr), { name: 'HMAC', hash: SUBTLE[algo] }, false, ['sign']);
      const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(text));
      return { algorithm: `hmac-${algo}`, hex: toHex(sig) };
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

function reqStr(args: Record<string, unknown>, key: string, ex: string): string {
  const v = args[key];
  // Allow the empty string (hashing "" is valid); only reject non-strings.
  if (typeof v !== 'string') throw new Error(`Required argument "${key}" is missing. Pass a string like ${ex}.`);
  return v;
}

export default { tools, callTool, meter: { credits: 1 } } satisfies McpToolExport;
