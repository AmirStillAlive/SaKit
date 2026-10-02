/**
 * NPV Tunnel configuration decryption (.npvt format).
 *
 * Format:  NPVT1\n<base64>,<base64>,...
 * Cipher:  AES-128-CTR with white-box key tables (derived from the open-source
 *          Pantegnos project, MIT license: https://github.com/FrontierTM/Pantegnos).
 *
 * Execution is 100% client-side within the browser; zero external network requests.
 */

export const SHIFT_ORDER = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

/** @type {{TY: Uint32Array, MBL: Uint32Array, XT: Uint8Array, TBL: Uint8Array}|null} */
let TABLES = null;

/** Initializes white-box tables from parsed JSON (npv_tables.json). */
export function setTables(json) {
  TABLES = {
    TY: Uint32Array.from(json.tyBoxes.data),
    MBL: Uint32Array.from(json.mbl.data),
    XT: Uint8Array.from(json.xorTable.data),
    TBL: Uint8Array.from(json.tboxesLast.data),
  };
  return TABLES;
}

export function hasTables() {
  return TABLES !== null;
}

/** Core transformation: transforms one 16-byte block using white-box lookup tables. */
export function core(block) {
  const { TY, MBL, XT, TBL } = TABLES;
  let buf = new Uint8Array(16);
  for (let i = 0; i < 16; i++) buf[i] = block[SHIFT_ORDER[i]];

  for (let i11 = 0; i11 < 4; i11++) {
    const i13 = i11 * 4;
    const i14 = i13 + 1, i15 = i13 + 2, i16 = i13 + 3;

    const iC  = TY[i13 * 256 + buf[i13]];
    const iC2 = TY[i14 * 256 + buf[i14]];
    const iC3 = TY[i15 * 256 + buf[i15]];
    const iC4 = TY[i16 * 256 + buf[i16]];

    // First round transformation: tyBoxes mixed with xorTable
    for (let i17 = 0; i17 < 4; i17++) {
      const i18 = i11 * 24 + i17 * 6;
      const i19 = i17 * 8;
      const i20 = 28 - i19;
      const i22 = 24 - i19;

      const n1 = (iC  >>> i20) & 15, n2 = (iC2 >>> i20) & 15;
      const n3 = (iC3 >>> i20) & 15, n4 = (iC4 >>> i20) & 15;
      const b10 = XT[(i18 * 16 + n1) * 16 + n2];
      const b11 = XT[(i18 * 16 + n3) * 16 + n4];

      const m1 = (iC  >>> i22) & 15, m2 = (iC2 >>> i22) & 15;
      const m3 = (iC3 >>> i22) & 15, m4 = (iC4 >>> i22) & 15;
      const lo = XT[(i18 + 5) * 256 + XT[(i18 + 2) * 256 + m1 * 16 + m2] * 16
                             + XT[(i18 + 3) * 256 + m3 * 16 + m4]];
      const hi = XT[(i18 + 4) * 256 + b10 * 16 + b11];

      buf[i13 + i17] = lo | (hi << 4);
    }

    // Second round transformation: mbl mixed with xorTable
    const iC5 = MBL[i13 * 256 + buf[i13]];
    const iC6 = MBL[i14 * 256 + buf[i14]];
    const iC7 = MBL[i15 * 256 + buf[i15]];
    const iC8 = MBL[i16 * 256 + buf[i16]];

    for (let i27 = 0; i27 < 4; i27++) {
      const i28 = i11 * 24 + i27 * 6;
      const i29 = i27 * 8;
      const i30 = 28 - i29;
      const i31 = 24 - i29;

      const n1 = (iC5 >>> i30) & 15, n2 = (iC6 >>> i30) & 15;
      const n3 = (iC7 >>> i30) & 15, n4 = (iC8 >>> i30) & 15;
      const a1 = XT[(i28 * 16 + n1) * 16 + n2];
      const a2 = XT[(i28 * 16 + n3) * 16 + n4];
      const hi = XT[(i28 + 4) * 256 + a1 * 16 + a2];

      const m1 = (iC5 >>> i31) & 15, m2 = (iC6 >>> i31) & 15;
      const m3 = (iC7 >>> i31) & 15, m4 = (iC8 >>> i31) & 15;
      const b1 = XT[(i28 + 2) * 256 + m1 * 16 + m2];
      const b2 = XT[(i28 + 3) * 256 + m3 * 16 + m4];
      const lo = XT[(i28 + 5) * 256 + b1 * 16 + b2];

      buf[i13 + i27] = (hi << 4) | lo;
    }
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = TBL[i * 256 + buf[SHIFT_ORDER[i]]];
  return out;
}

/** AES-CTR with white-box core; big-endian 16-byte counter block. */
export function ctr(nonce, data) {
  const counter = Uint8Array.from(nonce);
  const out = new Uint8Array(data.length);
  const ks = new Uint8Array(16);
  for (let off = 0; off < data.length; off += 16) {
    ks.set(core(counter));
    for (let i = 15; i >= 0; i--) {
      counter[i] = (counter[i] + 1) & 0xff;
      if (counter[i]) break;
    }
    const n = Math.min(16, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}

/** Decodes Base64 to byte array, tolerating whitespace and omitted padding. */
export function b64decode(s) {
  const clean = s.replace(/\s+/g, '');
  if (!clean) return new Uint8Array(0);
  const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Decrypts a Base64-encoded block (16-byte nonce prepended). */
export function decryptBlob(data) {
  if (data.length < 32) return new Uint8Array(0);
  return ctr(data.subarray(0, 16), data.subarray(16));
}

/** Decodes UTF-8 bytes to string. */
export function utf8decode(bytes) {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

/**
 * Detects format from textual content: npvt, npv, or unknown.
 * @param {string} text
 */
export function detectFormat(text) {
  const head = text.trimStart().slice(0, 64);
  if (head.startsWith('NPVS')) return 'npv';
  if (head.includes('NPVT1') || head.includes('NPVTSUB1')) return 'npvt';
  const toks = text.split(',').map((t) => t.trim()).filter(Boolean);
  if (toks.length && toks.every((t) => /^[A-Za-z0-9+/=\s]+$/.test(t))) return 'npvt';
  return 'unknown';
}

/**
 * Decrypts all tokens in .npvt file text into an array of plaintext Uint8Array payloads.
 * @param {string} text
 * @returns {Uint8Array[]}
 */
export function decryptFileText(text) {
  const out = [];
  for (let tok of text.replace(/NPVTSUB1/g, ',').replace(/NPVT1/g, ',').split(',')) {
    tok = tok.trim();
    if (!tok) continue;
    let blob;
    try {
      blob = b64decode(tok);
    } catch {
      continue;
    }
    if (blob.length < 32) continue;
    const pt = decryptBlob(blob);
    if (pt.length) out.push(pt);
  }
  return out;
}

/** Formats byte array as pretty-printed JSON if valid, else returns raw UTF-8 string. */
export function pretty(bytes) {
  const raw = utf8decode(bytes);
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

/**
 * Builds an import link from one decrypted config.
 * For full multi-protocol support, prefer src/lib/links.ts.
 */
export function toVmessLink(obj) {
  const p = obj && obj.v2rayProfile;
  if (!p || !p.server) return null;
  const remark = String(obj.name || p.remarks || '').trim();
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const sec = String(p.security || '').toLowerCase();
  const isTls = sec === 'tls' || sec === 'reality';
  const id = String(p.password || '');
  const b64 = (s) => btoa(unescape(encodeURIComponent(s)));

  if (String(p.configType) === '3') {
    const method = String(p.method || '').trim();
    if (!method && !id) return null;
    const userInfo = method.includes(':') ? method : method ? `${method}:${id}` : id;
    return `ss://${b64(userInfo)}@${p.server}:${p.serverPort}#${encodeURIComponent(remark)}`;
  }

  if (!UUID_RE.test(id)) return null;

  const inner = {
    v: '2',
    ps: remark,
    add: p.server,
    port: String(p.serverPort),
    id,
    aid: '0',
    scy: 'auto',
    net: p.network || 'tcp',
    type: p.headerType || 'none',
    host: p.host || '',
    path: p.path || '',
    tls: isTls ? 'tls' : '',
    sni: p.sni || '',
    fp: p.fingerPrint || '',
    alpn: p.alpn || '',
  };
  return 'vmess://' + b64(JSON.stringify(inner));
}

/** Triggers a browser download for text content. */
export function downloadText(filename, content) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
