/**
 * npvs_gen2.js: باز کردن نسخهٔ ۵ (.npvs نسل جدید، پاکت فشرده gen2)
 *
 * پورت جاوااسکریپت از پروژهٔ Pantegnos (پروانه MIT):
 *   internal/modules/impl/npvs_gen2.go
 *   internal/modules/impl/npvs_gen2_wb.go
 *
 * مسیر appKey (method=2) بدون رمز و کاملا آفلاین باز می‌شود چون جدول‌های
 * white-box نسل ۲ داخل خود همین صفحه است. مسیر passphrase (method=1) به رمز
 * نیاز دارد و method=0 (گیرنده) به کلید خصوصی.
 *
 * جدول‌ها در فایل ثابت gen2_tables.bin.z کنار صفحه هستند و فقط وقتی فایل
 * نسخهٔ ۵ بدهید دانلود می‌شوند (zlib -> ۱۴۹۵۶۸ بایت خام).
 */

import {
  NpvsError,
  NeedsPassphrase,
  chachaOpen,
  decodeSentinels,
} from './npvs.js';
import { gen2Sub7dc0 } from './npvs_gen2_sub7dc0.js';

export const ENVELOPE_VERSION = 5;
export const HEADER_FIXED = 135;
export const KEY_BLOCK_OFFSET = 53;
export const SENTINEL_SEQ = 0xffff;
export const METHOD_RECIPIENT = 0;
export const METHOD_PASS = 1;
export const METHOD_APPKEY = 2;
export const RECIPIENT_PK_SIZE = 32;
export const RECIPIENT_WRAP_SIZE = 0x5d;
export const PASS_BLOCK_SIZE = 80;
export const APPKEY_BLOCK_SIZE = 78;
export const SIG_SIZE = 64;
export const MIN_ITERS = 1;
export const MAX_ITERS = 10000000;

export const METADATA_INFO = 'NPVS-v5/metadata';
export const FIELD_KEY_INFO = 'NPV-fields-v1/field/';
export const RECORD_AAD_INFO = 'NPV-fields-v1/record/';
export const BODY_MAGIC = [0x4e, 0x50, 0x46, 0x01]; // "NPF\x01"
export const GEN2_APPKEY_LABEL = 'npvtunnel/appkey/v2 ';

export const GEN2_BLOCK_SIZE = 57344;
export const GEN2_BLOCK_COUNT = 13;
export const GEN2_PAGE_SIZE = 4096;
export const GEN2_TABLES_SIZE =
  GEN2_BLOCK_COUNT * GEN2_BLOCK_SIZE + GEN2_PAGE_SIZE;

const GEN2_SHIFT_ROWS = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

const TE = new TextEncoder();

/** @type {Uint8Array|null} */
let GEN2_TABLES = null;

/** جدول‌های بازشده را دستی می‌دهد (تست‌ها و لودر مرورگر). */
export function setGen2Tables(bytes) {
  if (bytes.length !== GEN2_TABLES_SIZE) {
    throw new NpvsError(
      `جدول‌های نسل ۲ باید ${GEN2_TABLES_SIZE} بایت باشند، نه ${bytes.length}`,
    );
  }
  GEN2_TABLES = bytes;
  return GEN2_TABLES;
}

export function hasGen2Tables() {
  return GEN2_TABLES !== null;
}

/** فایل ثابت gen2_tables.bin.z را می‌گیرد و با zlib باز می‌کند. */
export async function loadGen2Tables(url = './gen2_tables.bin.z') {
  if (GEN2_TABLES) return GEN2_TABLES;
  const res = await fetch(url);
  if (!res.ok) {
    throw new NpvsError('فایل جدول‌های نسخهٔ ۵ در دسترس نیست.');
  }
  const packed = new Uint8Array(await res.arrayBuffer());
  if (typeof DecompressionStream === 'undefined') {
    throw new NpvsError('مرورگر شما از باز کردن جدول‌های فشرده پشتیبانی نمی‌کند.');
  }
  const stream = new Blob([packed]).stream().pipeThrough(new DecompressionStream('deflate'));
  const raw = new Uint8Array(await new Response(stream).arrayBuffer());
  return setGen2Tables(raw);
}

// ---------------------------------------------------------------------------
// هستهٔ white-box نسل ۲
// ---------------------------------------------------------------------------

function be32(block, off) {
  return (
    ((block[off] << 24) |
      (block[off + 1] << 16) |
      (block[off + 2] << 8) |
      block[off + 3]) >>>
    0
  );
}

function groupArgs(block, half, j, s) {
  const base = half + 0x1000 * j;
  return [
    be32(block, base + 4 * s[0]),
    be32(block, base + 0x400 + 4 * s[1]),
    be32(block, base + 0x800 + 4 * s[2]),
    be32(block, base + 0xc00 + 4 * s[3]),
  ];
}

function shiftState(state) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = state[GEN2_SHIFT_ROWS[i]];
  return out;
}

/** خروجی ۱۶ بایتی white-box نسل ۲ از روی نمک ۱۶ بایتی. */
export function gen2A16(salt) {
  if (!GEN2_TABLES) throw new NpvsError('جدول‌های نسل ۲ بارگذاری نشده‌اند.');
  if (salt.length !== 16) {
    throw new NpvsError(`نمک gen2 باید ۱۶ بایت باشد، نه ${salt.length}`);
  }

  let state = Uint8Array.from(salt);
  for (let b = 0; b < GEN2_BLOCK_COUNT; b++) {
    const block = GEN2_TABLES.subarray(
      b * GEN2_BLOCK_SIZE,
      (b + 1) * GEN2_BLOCK_SIZE,
    );
    state = shiftState(state);
    for (let j = 0; j < 4; j++) {
      let s = [state[4 * j], state[4 * j + 1], state[4 * j + 2], state[4 * j + 3]];
      s = gen2Sub7dc0(block, j, ...groupArgs(block, 0x6000, j, s));
      s = gen2Sub7dc0(block, j, ...groupArgs(block, 0xa000, j, s));
      state[4 * j] = s[0];
      state[4 * j + 1] = s[1];
      state[4 * j + 2] = s[2];
      state[4 * j + 3] = s[3];
    }
  }

  const page = GEN2_TABLES.subarray(GEN2_BLOCK_COUNT * GEN2_BLOCK_SIZE);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = page[0x100 * i + state[GEN2_SHIFT_ROWS[i]]];
  }
  return out;
}

/** KDK نسل ۲: SHA-256 روی (label + a16 + configID). */
export async function gen2Kdk(a16, configId) {
  const buf = new Uint8Array(GEN2_APPKEY_LABEL.length + a16.length + configId.length);
  buf.set(TE.encode(GEN2_APPKEY_LABEL), 0);
  buf.set(a16, GEN2_APPKEY_LABEL.length);
  buf.set(configId, GEN2_APPKEY_LABEL.length + a16.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
}

/** HKDF-SHA256 با WebCrypto (همان الگوی Go). */
async function hkdfSha256(ikm, salt, info, outLen = 32) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt.length ? salt : new Uint8Array(outLen),
      info: typeof info === 'string' ? TE.encode(info) : info,
    },
    key,
    outLen * 8,
  );
  return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// تجزیهٔ پاکت فشردهٔ v5
// ---------------------------------------------------------------------------

export function isGen2Envelope(data) {
  return (
    data.length >= 9 &&
    data[0] === 0x4e &&
    data[1] === 0x50 &&
    data[2] === 0x56 &&
    data[3] === 0x53 &&
    data[4] === ENVELOPE_VERSION
  );
}

/** پاکت فشردهٔ v5 را می‌شکافد (آفست‌ها عینا از Go). */
export function parseGen2Envelope(data) {
  if (!isGen2Envelope(data)) throw new NpvsError('پاکت فشردهٔ نسخهٔ ۵ نیست');

  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const hdrLen = dv.getUint32(5, false);
  if (hdrLen < HEADER_FIXED || 9 + hdrLen > data.length) {
    throw new NpvsError(`طول سرآیند نامعتبر: ${hdrLen}`);
  }
  const h = data.subarray(9, 9 + hdrLen);
  if (h[0] !== 1) {
    throw new NpvsError(`نسخهٔ سرآیند فشرده پشتیبانی نمی‌شود: ${h[0]}`);
  }

  const env = {
    header: h,
    configId: h.subarray(1, 17),
    creator: h.subarray(17, 50),
    method: h[50],
  };
  if (![METHOD_RECIPIENT, METHOD_PASS, METHOD_APPKEY].includes(env.method)) {
    throw new NpvsError(`روش باز کردن ناشناخته: ${env.method}`);
  }

  const recipients = (h[51] << 8) | h[52];
  if (recipients > 0x400) {
    throw new NpvsError(`تعداد گیرنده خیلی زیاد است: ${recipients}`);
  }
  if (env.method === METHOD_RECIPIENT && recipients === 0) {
    throw new NpvsError('سرآیند پاکت فشرده نامعتبر است');
  }
  env.recipients = recipients;

  let off = KEY_BLOCK_OFFSET + recipients * (RECIPIENT_PK_SIZE + RECIPIENT_WRAP_SIZE);
  if (env.method === METHOD_PASS) {
    if (off + PASS_BLOCK_SIZE + 4 > h.length) {
      throw new NpvsError('بلوک passphrase بریده شده است');
    }
    env.iters = h[off] * 0x1000000 + (h[off + 1] << 16) + (h[off + 2] << 8) + h[off + 3];
    if (env.iters < MIN_ITERS || env.iters > MAX_ITERS) {
      throw new NpvsError(`تعداد تکرار نامعتبر: ${env.iters}`);
    }
    env.salt = h.subarray(off + 4, off + 20);
    env.wrap = h.subarray(off + 20, off + PASS_BLOCK_SIZE);
    off += PASS_BLOCK_SIZE;
  } else if (env.method === METHOD_APPKEY) {
    if (off + APPKEY_BLOCK_SIZE + 4 > h.length) {
      throw new NpvsError('بلوک appKey بریده شده است');
    }
    if (((h[off] << 8) | h[off + 1]) !== METHOD_APPKEY) {
      throw new NpvsError('بلوک appKey پیدا نشد');
    }
    env.salt = h.subarray(off + 2, off + 18);
    env.wrap = h.subarray(off + 18, off + APPKEY_BLOCK_SIZE);
    off += APPKEY_BLOCK_SIZE;
  }

  if (off + 4 > h.length) {
    throw new NpvsError('طول متاباب مهرشده بریده شده است');
  }
  const metaLen =
    h[off] * 0x1000000 + (h[off + 1] << 16) + (h[off + 2] << 8) + h[off + 3];
  if (metaLen < 16 || off + 4 + metaLen > h.length) {
    throw new NpvsError(`طول متاباب مهرشده نامعتبر: ${metaLen}`);
  }
  env.prefix = h.subarray(0, off);
  env.metaBlob = h.subarray(off + 4, off + 4 + metaLen);

  off = 9 + hdrLen;
  if (off + 16 > data.length) {
    throw new NpvsError('سرآیند بدنه بریده شده است');
  }
  env.nonce = data.subarray(off, off + 12);
  const bodyLen = dv.getUint32(off + 12, false);
  off += 16;
  if (bodyLen < 32 || off + bodyLen + SIG_SIZE > data.length) {
    throw new NpvsError(`طول بدنه نامعتبر: ${bodyLen}`);
  }
  env.body = data.subarray(off, off + bodyLen);
  env.sig = data.subarray(off + bodyLen, off + bodyLen + SIG_SIZE);
  return env;
}

/** بدنهٔ NPF: contentID + فهرست (seq, flags, blob). */
export function parseGen2Body(body) {
  if (
    body.length < 66 ||
    body[0] !== BODY_MAGIC[0] ||
    body[1] !== BODY_MAGIC[1] ||
    body[2] !== BODY_MAGIC[2] ||
    body[3] !== BODY_MAGIC[3]
  ) {
    throw new NpvsError('بدنهٔ NPF نامعتبر است');
  }
  const contentId = body.subarray(4, 36);
  const count = (body[36] << 8) | body[37];
  let off = 38;
  const rows = [];
  for (let i = 0; i < count; i++) {
    if (off + 6 > body.length) throw new NpvsError('سربرگ فیلد NPF بریده شده است');
    const seq = (body[off] << 8) | body[off + 1];
    const flags = (body[off + 2] << 8) | body[off + 3];
    const blobLen = (body[off + 4] << 8) | body[off + 5];
    if (off + 6 + blobLen > body.length) {
      throw new NpvsError('بستهٔ فیلد NPF بریده شده است');
    }
    rows.push({ seq, flags, blob: body.subarray(off + 6, off + 6 + blobLen) });
    off += 6 + blobLen;
  }
  return { contentId, rows };
}

// ---------------------------------------------------------------------------
// باز کردن کلید و محتوا
// ---------------------------------------------------------------------------

async function pbkdf2Sha256(password, salt, iterations, dkLen = 32) {
  const base = await crypto.subtle.importKey('raw', TE.encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    dkLen * 8,
  );
  return new Uint8Array(bits);
}

/** پاکت را باز می‌کند: DEK + متادیتای خوانا + فهرست کلیدها. */
export async function gen2Open(env, password = '') {
  let kdk;
  const methodKeys = [];

  if (env.method === METHOD_APPKEY) {
    const a16 = gen2A16(env.salt);
    kdk = await gen2Kdk(a16, env.configId);
    methodKeys.push(['appKey A16 (gen-2 whitebox)', bytesToHex(a16)]);
  } else if (env.method === METHOD_PASS) {
    if (!password) {
      throw new NeedsPassphrase('برای باز کردن این فایل نسخهٔ ۵ به رمز عبور نیاز است');
    }
    kdk = await pbkdf2Sha256(password, env.salt, env.iters);
    methodKeys.push(['kdf', `pbkdf2-hmac-sha256 iterations=${env.iters}`]);
  } else {
    throw new NpvsError(`روش باز کردن ${env.method} به کلید خصوصی گیرنده نیاز دارد`);
  }

  const dek = chachaOpen(kdk, env.wrap.subarray(0, 12), env.wrap.subarray(12), env.salt);
  if (!dek) {
    if (env.method === METHOD_PASS) throw new NeedsPassphrase('رمز عبور درست نیست');
    throw new NpvsError('باز کردن پاکت کلید ناموفق بود');
  }

  // متاباب: AAD همان بایت‌های سرآیند تا قبل از طول متاباب است
  const metaKey = await hkdfSha256(dek, env.nonce, METADATA_INFO);
  const metadata = chachaOpen(metaKey, env.nonce, env.metaBlob, env.prefix);
  if (!metadata) throw new NpvsError('متاباب مهرشده باز نشد');

  const keys = [
    ['configId', bytesToHex(env.configId)],
    ['creator.pk', bytesToHex(env.creator)],
    ...methodKeys,
    ['KDK', bytesToHex(kdk)],
    ['DEK/CEK', bytesToHex(dek)],
  ];
  return { dek, metadata, keys };
}

/** فیلدهای NPF را یکی‌یکی باز می‌کند. */
export async function decryptGen2Fields(env, dek) {
  const { contentId, rows } = parseGen2Body(env.body);
  const fields = new Map();

  for (const row of rows) {
    const ptLen = row.blob.length - 16;
    if (ptLen < 0) continue;
    const seqBytes = new Uint8Array([row.seq >> 8, row.seq & 0xff]);
    const key = await hkdfSha256(dek, contentId, concat(FIELD_KEY_INFO, seqBytes));
    const aad = concat(
      RECORD_AAD_INFO,
      contentId,
      seqBytes,
      new Uint8Array([(ptLen >>> 24) & 0xff, (ptLen >>> 16) & 0xff, (ptLen >>> 8) & 0xff, ptLen & 0xff]),
    );
    const pt = chachaOpen(key, new Uint8Array(12), row.blob, aad);
    if (pt) fields.set(row.seq, pt);
  }
  return { contentId, fields };
}

function concat(...parts) {
  const arrs = parts.map((p) => (typeof p === 'string' ? TE.encode(p) : p));
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function bytesToHex(b) {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

/** متن یک فیلد را تمیز می‌کند (رشتهٔ JSON داخل گیومه را هم باز می‌کند). */
function fieldText(raw) {
  const s = new TextDecoder().decode(raw).trim();
  if (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"') {
    try {
      return JSON.parse(s);
    } catch {
      return s.slice(1, -1);
    }
  }
  return s;
}

/** جدول sentinel (seq=0xFFFF) را به فهرست کانفیگ‌ها تبدیل می‌کند. */
export function gen2Configs(fields) {
  const table = fields.get(SENTINEL_SEQ);
  if (!table) return null;

  const substitute = (v) => {
    if (typeof v === 'boolean') return v;
    if (typeof v === 'number' && Number.isInteger(v)) {
      const raw = fields.get(v);
      return raw ? decodeSentinels(fieldText(raw)) : '';
    }
    if (Array.isArray(v)) return v.map(substitute);
    if (v && typeof v === 'object') {
      const out = {};
      for (const [k, x] of Object.entries(v)) out[k] = substitute(x);
      return out;
    }
    return v;
  };

  const spec = JSON.parse(new TextDecoder().decode(table));
  return (spec.configs ?? []).map(substitute);
}

// ---------------------------------------------------------------------------
// نقطهٔ ورود
// ---------------------------------------------------------------------------

/** فایل نسخهٔ ۵ را باز می‌کند و همان ساختار خروجی نسخهٔ ۱ را برمی‌گرداند. */
export async function decryptNpvsGen2(data, password = '') {
  const env = parseGen2Envelope(data);
  const { dek, metadata, keys } = await gen2Open(env, password);
  const { fields } = await decryptGen2Fields(env, dek);

  let configs = gen2Configs(fields);
  if (configs === null) {
    configs = [...fields.entries()]
      .filter(([seq]) => seq !== SENTINEL_SEQ)
      .sort((a, b) => a[0] - b[0])
      .map(([seq, raw]) => ({ seq, text: new TextDecoder().decode(raw) }));
  }

  let meta = null;
  try {
    meta = JSON.parse(new TextDecoder().decode(metadata));
  } catch {
    meta = null;
  }
  const policy = meta?.policy ?? {};
  const creatorMessage = ['customServerMessage', 'displayMessage']
    .map((k) => String(policy[k] ?? '').trim())
    .filter(Boolean)
    .join('\n');

  return {
    format: 'npvs',
    plaintext: JSON.stringify(configs, null, 2),
    json: configs,
    meta: {
      version: ENVELOPE_VERSION,
      configId: bytesToHex(env.configId),
      issuedAt: meta?.issuedAt ?? null,
      policy,
      creatorMessage,
      signature: bytesToHex(env.sig),
    },
    keys,
    notes: [
      env.method === METHOD_APPKEY
        ? 'رمزگشایی با جدول‌های بازمتن نسل ۲ (White-Box) انجام شد؛ بدون نیاز به رمز عبور.'
        : 'رمزگشایی با رمز عبور کاربر و PBKDF2 انجام شد.',
    ],
  };
}
