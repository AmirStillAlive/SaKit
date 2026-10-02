/**
 * npvs.js: NPVS format decryption (NPV Tunnel / NapsternetV configuration).
 *
 * JavaScript port of Go source from Pantegnos project (MIT License):
 *   internal/modules/impl/npvs.go
 *   internal/modules/impl/npvs_wb.go
 *
 * Unlike .npvt, the NPVS file is a full envelope with a JSON header and
 * payload protected by ChaCha20-Poly1305. The key is derived via either:
 *   1) appKey embedded in app (white-box) -> key derivation without password
 *   2) passphrase with PBKDF2-HMAC-SHA256 -> requires user password
 *
 * Client-side processing with no backend required for normal operations.
 */

const MAGIC = [0x4e, 0x50, 0x56, 0x53]; // "NPVS"
const MIN_LEN = 89;
const WRAP_SIZE = 60;
const SALT_SIZE = 16;
const SIG_SIZE = 64;
const KDF_APPKEY = 'wbaes-ctr-sha256';
const KDF_PASS = 'pbkdf2-hmac-sha256';
const KEYGEN = 1;
const MAX_ITERS = 10000000;

const WB_KDF_PREFIX = new TextEncoder().encode('npvtunnel/appkey/v1 ');
const WB_SHIFT_ROWS = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

const SENTINEL_PREFIX = 'npvs1:';
const SENTINEL_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-';

const POLY_P = (1n << 130n) - 5n;
const LE = new DataView(new ArrayBuffer(8));

/** Converts a byte array to little-endian BigInt. */
function bytesToLe(bytes, off = 0, len = 8) {
  let v = 0n;
  for (let i = len - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[off + i]);
  return v;
}

/** NPVS error class. */
export class NpvsError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NpvsError';
  }
}

/** Thrown when file is passphrase-protected and password is missing or incorrect. */
export class NeedsPassphrase extends NpvsError {
  constructor(message, creatorMessage = '') {
    super(message);
    this.name = 'NeedsPassphrase';
    this.creatorMessage = creatorMessage;
  }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 (RFC 8439)
// ---------------------------------------------------------------------------

const CHACHA_CONST = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

function rotl32(v, n) {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

function chacha20Block(key, counter, nonce, out) {
  const state = new Uint32Array(16);
  state.set(CHACHA_CONST, 0);
  for (let i = 0; i < 8; i++) {
    const o = i * 4;
    state[4 + i] =
      (key[o] | (key[o + 1] << 8) | (key[o + 2] << 16) | (key[o + 3] << 24)) >>> 0;
  }
  state[12] = counter >>> 0;
  for (let i = 0; i < 3; i++) {
    const o = i * 4;
    state[13 + i] =
      (nonce[o] | (nonce[o + 1] << 8) | (nonce[o + 2] << 16) | (nonce[o + 3] << 24)) >>> 0;
  }

  const x = state.slice();
  const qr = (a, b, c, d) => {
    x[a] = (x[a] + x[b]) >>> 0;
    x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0;
    x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0;
    x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0;
    x[b] = rotl32(x[b] ^ x[c], 7);
  };

  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }

  for (let i = 0; i < 16; i++) {
    const w = (x[i] + state[i]) >>> 0;
    out[i * 4] = w & 0xff;
    out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff;
    out[i * 4 + 3] = (w >>> 24) & 0xff;
  }
  return out;
}

function chacha20Xor(key, counter, nonce, data) {
  const out = new Uint8Array(data.length);
  const ks = new Uint8Array(64);
  for (let off = 0, ctr = counter; off < data.length; off += 64, ctr++) {
    chacha20Block(key, ctr, nonce, ks);
    const n = Math.min(64, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}


/** Poly1305 MAC implementation using BigInt for one-time tag computation. */
function poly1305(msg, key) {
  const r = bytesToLe(key, 0, 16) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const s = bytesToLe(key, 16, 16);

  let acc = 0n;
  for (let off = 0; off < msg.length; off += 16) {
    const n = Math.min(16, msg.length - off);
    const chunk = new Uint8Array(17);
    chunk.set(msg.subarray(off, off + n));
    // Append 1-bit padding to final chunk
    chunk[n] = 1;
    acc = ((acc + bytesToLe(chunk, 0, 17)) * r) % POLY_P;
  }

  const tag = new Uint8Array(16);
  let v = (acc + s) & ((1n << 128n) - 1n);
  for (let i = 0; i < 16; i++) {
    tag[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return tag;
}

/** Constant-time comparison for authentication tags of equal length. */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Formats Poly1305 MAC input according to RFC 8439: aad || pad || ct || pad || lens. */
function poly1305Input(aad, ct) {
  const pad = (n) => new Uint8Array((16 - (n % 16)) % 16);
  const mac = new Uint8Array(aad.length + pad(aad.length).length + ct.length + pad(ct.length).length + 16);
  let o = 0;
  mac.set(aad, o); o += aad.length;
  o += pad(aad.length).length;
  mac.set(ct, o); o += ct.length;
  o += pad(ct.length).length;
  LE.setBigUint64(0, BigInt(aad.length), true);
  mac.set(new Uint8Array(LE.buffer), o); o += 8;
  LE.setBigUint64(0, BigInt(ct.length), true);
  mac.set(new Uint8Array(LE.buffer), o);
  return mac;
}

/** Decrypts ChaCha20-Poly1305; returns null if tag verification fails. */
export function chachaOpen(key, nonce, ctAndTag, aad) {
  if (nonce.length !== 12 || ctAndTag.length < 16) return null;

  const ct = ctAndTag.subarray(0, ctAndTag.length - 16);
  const tag = ctAndTag.subarray(ctAndTag.length - 16);

  const otk = chacha20Block(key, 0, nonce, new Uint8Array(64)).subarray(0, 32);
  const expected = poly1305(poly1305Input(aad, ct), otk);
  if (!timingSafeEqual(expected, tag)) return null;

  return chacha20Xor(key, 1, nonce, ct);
}

/** Encrypts ChaCha20-Poly1305; used for generating test vectors. */
export function chachaSeal(key, nonce, plaintext, aad) {
  const otk = chacha20Block(key, 0, nonce, new Uint8Array(64)).subarray(0, 32);
  const ct = chacha20Xor(key, 1, nonce, plaintext);
  const tag = poly1305(poly1305Input(aad, ct), otk);
  const out = new Uint8Array(ct.length + 16);
  out.set(ct, 0);
  out.set(tag, ct.length);
  return out;
}



// ---------------------------------------------------------------------------
// White-box core for KDF
// ---------------------------------------------------------------------------

/** @type {{ty: Uint32Array, mbl: Uint32Array, xor: Uint8Array, v1: Uint8Array, v2: Uint8Array}|null} */
let WB = null;

function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function be32Table(bytes) {
  const out = new Uint32Array(16 * 256);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < 16 * 256; i++) out[i] = dv.getUint32(i * 4, false);
  return out;
}

/** Initializes white-box lookup tables once. */
export function setWbTables(json) {
  const t = json.tables;
  WB = {
    ty: be32Table(b64ToBytes(t.tyboxes.data)),
    mbl: be32Table(b64ToBytes(t.mbl.data)),
    xor: b64ToBytes(t.xor.data),
    v1: b64ToBytes(t.tboxes_last.data),
    v2: b64ToBytes(t.tboxes_last_v2.data),
  };
  return WB;
}

export function hasWbTables() {
  return WB !== null;
}

function wbXor(t, a, b) {
  return WB.xor[(t << 8) + (a << 4) + b];
}

function wbMix(grp, k, a, b, c, d) {
  const t = grp * 24 + k * 6;
  const hi = 28 - 8 * k;
  const lo = 24 - 8 * k;
  const p1 = wbXor(t, (a >>> hi) & 15, (b >>> hi) & 15);
  const p2 = wbXor(t + 1, (c >>> hi) & 15, (d >>> hi) & 15);
  const p3 = wbXor(t + 2, (a >>> lo) & 15, (b >>> lo) & 15);
  const p4 = wbXor(t + 3, (c >>> lo) & 15, (d >>> lo) & 15);
  return (wbXor(t + 4, p1, p2) << 4) | wbXor(t + 5, p3, p4);
}

/** Transforms a 16-byte block using white-box lookup tables. */
export function wbBlock(block, tlast) {
  if (!WB) throw new NpvsError('جدول‌های رمز هنوز بارگذاری نشده‌اند.');
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = block[WB_SHIFT_ROWS[i]];

  for (let grp = 0; grp < 4; grp++) {
    const base = grp * 4;
    for (const name of ['ty', 'mbl']) {
      const box = WB[name];
      const a = box[(base + 0) * 256 + s[base + 0]];
      const b = box[(base + 1) * 256 + s[base + 1]];
      const c = box[(base + 2) * 256 + s[base + 2]];
      const d = box[(base + 3) * 256 + s[base + 3]];
      for (let k = 0; k < 4; k++) s[base + k] = wbMix(grp, k, a, b, c, d);
    }
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = tlast[i * 256 + s[WB_SHIFT_ROWS[i]]];
  return out;
}

/** White-box AES-CTR implementation with final table substitution. */
export function wbCtr(nonce, data, tlast) {
  const counter = Uint8Array.from(nonce.subarray(0, 16));
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 16) {
    const ks = wbBlock(counter, tlast);
    const n = Math.min(16, data.length - off);
    for (let j = 0; j < n; j++) out[off + j] = data[off + j] ^ ks[j];
    for (let p = 15; p >= 0; p--) {
      counter[p] = (counter[p] + 1) & 0xff;
      if (counter[p]) break;
    }
  }
  return out;
}

/** SHA-256 digest using WebCrypto API. */
export async function sha256Async(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/**
 * Derived custodian keys from white-box tables for appKey decryption.
 * Generates separate keys for both final table generations.
 */
export async function custodianKdks(salt) {
  if (!WB) throw new NpvsError('جدول‌های رمز هنوز بارگذاری نشده‌اند.');
  const material = new Uint8Array(32);
  material.set(salt.subarray(0, 16), 0);

  const kdks = [];
  for (const tlast of [WB.v1, WB.v2]) {
    const stream = wbCtr(material.subarray(0, 16), material.subarray(16), tlast);
    const buf = new Uint8Array(WB_KDF_PREFIX.length + stream.length);
    buf.set(WB_KDF_PREFIX, 0);
    buf.set(stream, WB_KDF_PREFIX.length);
    kdks.push(await sha256Async(buf));
  }
  return kdks;
}


// ---------------------------------------------------------------------------
// Envelope parsing
// ---------------------------------------------------------------------------

/** Decodes URL-safe base64 with tolerant padding handling. */
function b64urlDecode(s) {
  // Convert base64url to standard base64
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  try {
    return b64ToBytes(padded);
  } catch {
    // Fallback to direct decoding if padding normalization fails
    try {
      return b64ToBytes(s + '='.repeat((4 - (s.length % 4)) % 4));
    } catch {
      throw new NpvsError('مقدار base64 نامعتبر است');
    }
  }
}

function hexToBytes(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(b) {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

/** PBKDF2-HMAC-SHA256 derivation via WebCrypto. */
async function pbkdf2Sha256(password, salt, iterations, dkLen) {
  const base = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    dkLen * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Parses NPVS envelope and extracts packet components.
 * Layout: "NPVS" | version (1) | header length (4 BE) | JSON
 *        | nonce (12) | body length (4 BE) | body | signature (64)
 */
export function parseEnvelope(data) {
  if (data.length < MIN_LEN) {
    throw new NpvsError(`فایل خیلی کوتاه است: ${data.length} بایت`);
  }
  for (let i = 0; i < 4; i++) {
    if (data[i] !== MAGIC[i]) throw new NpvsError('امضای NPVS پیدا نشد');
  }

  const version = data[4];
  if (version > 1) throw new NpvsError(`نسخهٔ پشتیبانی‌نشده: ${version}`);

  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const hdrLen = dv.getUint32(5, false);
  if (9 + hdrLen > data.length) {
    throw new NpvsError(`طول سرآیند نامعتبر: ${hdrLen}`);
  }

  const headerRaw = data.subarray(9, 9 + hdrLen);
  let hdr;
  try {
    hdr = JSON.parse(new TextDecoder().decode(headerRaw));
  } catch {
    throw new NpvsError('سرآیند JSON خوانده نشد');
  }

  let off = 9 + hdrLen;
  if (off + 16 > data.length) {
    throw new NpvsError('فایل وسط nonce یا طول بدنه بریده شده است');
  }

  const nonce = data.subarray(off, off + 12);
  const bodyLen = dv.getUint32(off + 12, false);
  off += 16;

  if (bodyLen < 16 || off + bodyLen + SIG_SIZE > data.length) {
    throw new NpvsError(`طول بدنه نامعتبر: ${bodyLen}`);
  }

  return {
    version,
    header: hdr,
    headerRaw,
    nonce,
    body: data.subarray(off, off + bodyLen),
    sig: data.subarray(off + bodyLen, off + bodyLen + SIG_SIZE),
  };
}

function creatorMessage(hdr) {
  const policy = hdr.policy || {};
  return ['customServerMessage', 'displayMessage']
    .map((k) => (policy[k] || '').trim())
    .filter(Boolean)
    .join('\n');
}

// ---------------------------------------------------------------------------
// Key unwrapping
// ---------------------------------------------------------------------------

async function unwrapAppKey(wrap) {
  if (wrap.kdf !== KDF_APPKEY) {
    throw new NpvsError(`KDF پشتیبانی‌نشده برای appKey: ${wrap.kdf}`);
  }
  if (wrap.keyId !== KEYGEN) {
    throw new NpvsError(`نسل کلید پیدا نشد: ${wrap.keyId}`);
  }

  const salt = b64urlDecode(wrap.salt);
  if (salt.length !== SALT_SIZE) {
    throw new NpvsError(`نمک باید ${SALT_SIZE} بایت باشد، نه ${salt.length}`);
  }

  const wrapBytes = b64urlDecode(wrap.wrap);
  if (wrapBytes.length !== WRAP_SIZE) {
    throw new NpvsError(`پاکت کلید باید ${WRAP_SIZE} بایت باشد، نه ${wrapBytes.length}`);
  }

  for (const kdk of await custodianKdks(salt)) {
    const dek = chachaOpen(kdk, wrapBytes.subarray(0, 12), wrapBytes.subarray(12), salt);
    if (dek) return dek;
  }
  throw new NpvsError('هیچ کلید custodian ای با این فایل نخواند');
}

async function unwrapPassphrase(wrap, password) {
  if (wrap.kdf !== KDF_PASS) {
    throw new NpvsError(`KDF پشتیبانی‌نشده برای passphrase: ${wrap.kdf}`);
  }
  if (!Number.isInteger(wrap.iters) || wrap.iters < 1 || wrap.iters > MAX_ITERS) {
    throw new NpvsError(`تعداد تکرار نامعتبر: ${wrap.iters}`);
  }
  if (!password) {
    throw new NpvsError('برای باز کردن این فایل به رمز عبور نیاز است');
  }

  const salt = b64urlDecode(wrap.salt);
  const wrapBytes = b64urlDecode(wrap.wrap);
  if (wrapBytes.length !== WRAP_SIZE) {
    throw new NpvsError(`پاکت کلید باید ${WRAP_SIZE} بایت باشد، نه ${wrapBytes.length}`);
  }

  const derived = await pbkdf2Sha256(password, salt, wrap.iters, 32);
  const dek = chachaOpen(derived, wrapBytes.subarray(0, 12), wrapBytes.subarray(12), salt);
  if (!dek) throw new NpvsError('رمز عبور درست نیست');
  return dek;
}

// ---------------------------------------------------------------------------
// Obfuscated sentinels
// ---------------------------------------------------------------------------

/** Decodes npvs1:<base64> sentinel strings back to original plaintext. */
export function decodeSentinels(text) {
  let out = '';
  let rest = text;
  for (;;) {
    const i = rest.indexOf(SENTINEL_PREFIX);
    if (i < 0) return out + rest;
    out += rest.slice(0, i);
    rest = rest.slice(i + SENTINEL_PREFIX.length);

    let j = 0;
    while (j < rest.length && SENTINEL_ALPHABET.includes(rest[j])) j++;
    const token = rest.slice(0, j);
    rest = rest.slice(j);

    // Return empty token unchanged
    if (!token) {
      out += SENTINEL_PREFIX;
      continue;
    }
    try {
      const padded = token + '='.repeat((4 - (token.length % 4)) % 4);
      out += new TextDecoder().decode(b64ToBytes(padded));
    } catch {
      out += SENTINEL_PREFIX + token;
    }
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Decrypts an NPVS file envelope.
 * @param {Uint8Array} data Raw file bytes
 * @param {string} [password] Passphrase for password-protected files
 */
export async function decryptNpvs(data, password = '') {
  const env = parseEnvelope(data);
  const hdr = env.header;

  const notes = [];
  const keys = [
    ['configId', String(hdr.configId || '')],
    ['creator.fp', String((hdr.creator || {}).fp || '')],
    ['creator.pk', String((hdr.creator || {}).pk || '')],
  ];

  let dek;
  try {
    if (hdr.appKey) {
      dek = await unwrapAppKey(hdr.appKey);
      notes.push('رمزگشایی با جدول‌های استاندارد White-Box انجام شد؛ بدون نیاز به رمز عبور.');
    } else if (hdr.passphrase) {
      dek = await unwrapPassphrase(hdr.passphrase, password);
      notes.push('رمزگشایی با رمز عبور کاربر و PBKDF2 انجام شد.');
    } else if (hdr.recipients && hdr.recipients.length) {
      throw new NpvsError(
        'این فایل برای گیرنده‌های مشخص رمز شده و به کلید خصوصی نیاز دارد.',
      );
    } else {
      throw new NpvsError('هیچ راه باز کردنی در سرآیند پیدا نشد.');
    }
  } catch (e) {
    if (hdr.passphrase && e instanceof NpvsError) {
      throw new NeedsPassphrase(e.message, creatorMessage(hdr));
    }
    throw e;
  }

  keys.push(['DEK/CEK', bytesToHex(dek)]);

  // ChaCha20 tag is located in the last 16 bytes of body; sig is an outer signature
  const plaintext = chachaOpen(dek, env.nonce, env.body, env.headerRaw);
  if (!plaintext) {
    throw new NpvsError('رمزگشایی محتوا شکست خورد؛ تگ تأیید نادرست است');
  }

  const text = decodeSentinels(new TextDecoder().decode(plaintext));

  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  return {
    format: 'npvs',
    plaintext: text,
    json,
    meta: {
      version: env.version,
      configId: hdr.configId,
      issuedAt: hdr.issuedAt,
      policy: hdr.policy || {},
      creatorMessage: creatorMessage(hdr),
      signature: bytesToHex(env.sig),
    },
    keys,
    notes,
  };
}
