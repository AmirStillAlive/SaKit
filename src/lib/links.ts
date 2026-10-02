// ساخت لینک ورود از روی خروجی رمزگشایی‌شده.
//
// ریشهٔ کار: فیلد v2rayProfile یک پاکت یکنواخت است و «نوع» کانفیگ را فقط
// configType می‌گوید. مقادیر دیده‌شده در فایل‌های واقعی:
//
//   configType === '3'  →  shadowsocks (پروتکل ss، نه v2ray)
//   configType === '5'  →  v2ray (vmess یا vless یا trojan)
//
// پیش از این بازسازی، همهٔ این‌ها به «vmess» تبدیل می‌شدند و لینک حاصل
// روی هیچ کلاینتی کار نمی‌کرد. مهم‌ترین نمونهٔ واقعی:
//
//   ss://…  با method = 2022-blake3-aes-128-gcm
//   → به vmess تبدیل می‌شد و id یک UUID نبود، پس کلاینت ردش می‌کرد.
//
// نکتهٔ دوم: security می‌تواند 'reality' باشد نه فقط 'tls'. در آن حالت
// فیلد tls در لینک vmess نباید خالی بماند، چون یعنی «بدون رمزنگاری».
// reality خودش یک لایهٔ TLS ایجاد می‌کند و کلاینت باید بداند.

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** نوع پروتکل واقعی، از روی configType و نه از شکل رمز. */
export type ConfigType = 'shadowsocks' | 'vless' | 'vmess' | 'trojan' | 'socks' | 'unknown';

/** خواندن configType به‌صورت tolerant: بعضی فایل‌ها عدد می‌دهند نه رشته. */
export function readConfigType(p: Record<string, any>): ConfigType {
  const raw = p.configType;
  const v = raw === undefined || raw === null ? '' : String(raw).trim();
  if (v === '1') return 'vmess';
  if (v === '2' || v === '3') return 'shadowsocks';
  if (v === '4') return 'socks';
  if (v === '5') return 'vless';
  if (v === '6') return 'trojan';
  if (v === '') {
    if (isReality(p) || p.publicKey || p.flow || p.encryption === 'none') return 'vless';
    if (p.headerType === 'http' && (p.security === 'none' || !p.security)) return 'vless';
    if (p.username && p.password && !UUID_RE.test(String(p.password))) return 'socks';
    const pw = String(p.password ?? '');
    if (UUID_RE.test(pw)) return 'vmess';
    if (hasTls(p) || p.sni) return 'trojan';
  }
  return 'unknown';
}

/** آیا لایهٔ TLS دارد؟ reality هم TLS دارد، پس هر دو «بله» هستند. */
export function hasTls(p: Record<string, any>): boolean {
  const s = String(p.security ?? '').toLowerCase();
  return s === 'tls' || s === 'reality';
}

export function isReality(p: Record<string, any>): boolean {
  return String(p.security ?? '').toLowerCase() === 'reality';
}

function b64encodeUnicode(s: string): string {
  return btoa(unescape(encodeURIComponent(s)));
}

export type BuiltLink = {
  kind: 'vmess' | 'vless' | 'trojan' | 'http' | 'socks' | 'shadowsocks';
  label: string;
  value: string;
};

/**
 * لینک shadowsocks به روش SIP002.
 *
 * قالب: ss://base64(method:password)@host:port#name
 *
 * فیلد password در v2rayProfile به شکل «method:password» است، پس قبل از
 * base64 کردن باید جای آن‌ها را عوض کنیم. برای SS-2022 طول رمز ثابت است
 * و همین ترتیب را در فیلد نگه می‌دارد.
 */
export function buildShadowsocksLink(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  if (!p.server || !p.serverPort) return null;

  const remark = String(item.name ?? p.remarks ?? '').trim();
  const method = String(p.method ?? '').trim();
  // v2rayProfile رمز را «method:password» می‌دهد؛ SIP002 «method:password»
  // می‌خواهد ولی رمز جداگانه دارد. اگر فقط یکی باشد، همان را می‌گذاریم.
  let userInfo: string;
  if (method && method.includes(':')) {
    userInfo = method; // از قبل «method:password» است
  } else if (method && p.password) {
    userInfo = `${method}:${p.password}`;
  } else if (p.password) {
    userInfo = String(p.password);
  } else {
    return null; // بدون رمز، شادوساکس بی‌معنی است
  }

  const user = b64encodeUnicode(userInfo);
  return {
    kind: 'shadowsocks',
    label: 'شادوساکس',
    value: `ss://${user}@${p.server}:${p.serverPort}#${encodeURIComponent(remark)}`,
  };
}

/**
 * لینک vmess. فقط وقتی ساخته می‌شود که رمز واقعاً UUID باشد؛ وگرنه
 * لینک بی‌معنی است و بهتر اصلاً ساخته نشود تا کاربر اشتباه نکند.
 */
export function buildVmessLink(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  const id = String(p.password ?? '');
  if (!p.server || !UUID_RE.test(id)) return null;
  const reality = isReality(p);
  const inner = {
    v: '2',
    ps: String(item.name ?? p.remarks ?? '').trim(),
    add: p.server,
    port: String(p.serverPort),
    id,
    aid: String(p.alterId ?? '0'),
    // در v2rayProfile، method شادوساکس نیست؛ رمزنگاری vmess اینجاست
    scy: 'auto',
    net: p.network || 'tcp',
    type: p.headerType || 'none',
    host: p.host || '',
    path: p.path || '',
    // reality هم TLS است؛ خالی گذاشتن یعنی «بدون رمزنگاری» و اشتباه است
    tls: hasTls(p) ? 'tls' : '',
    sni: p.sni || '',
    fp: p.fingerPrint || '',
    alpn: p.alpn || '',
  };
  // reality و flow در فرمت vmess جایی ندارند؛ در customJson می‌مانند
  void reality;
  return { kind: 'vmess', label: 'vmess', value: 'vmess://' + b64encodeUnicode(JSON.stringify(inner)) };
}

/** لینک vless برای پروفایل‌های configType=5 با رمز UUID. */
export function buildVlessFromProfile(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  const id = String(p.password ?? '');
  if (!p.server || !p.serverPort || !UUID_RE.test(id)) return null;
  const remark = String(item.name ?? p.remarks ?? '').trim();
  const reality = isReality(p);
  const q = new URLSearchParams();

  // امنیت: reality یا tls یا مقدار صریح یا none
  const sec = reality ? 'reality' : hasTls(p) ? 'tls' : (p.security || 'none');
  q.set('security', sec);

  // نوع شبکه (پیش‌فرض tcp)
  const net = p.network || 'tcp';
  q.set('type', net);

  // هدر (مانند http)
  if (p.headerType && p.headerType !== 'none') {
    q.set('headerType', p.headerType);
  }

  // هاست و مسیر
  if (p.host) q.set('host', p.host);
  if (p.path) q.set('path', p.path);

  // تنظیمات Reality
  if (reality) {
    if (p.publicKey) q.set('pbk', p.publicKey);
    if (p.shortId) q.set('sid', p.shortId);
    if (p.fingerPrint) q.set('fp', p.fingerPrint);
    if (p.spiderX) q.set('spx', p.spiderX);
  }

  // تنظیمات TLS
  if (p.sni) q.set('sni', p.sni);
  if (p.alpn) q.set('alpn', p.alpn);
  if (p.fingerPrint && !reality) q.set('fp', p.fingerPrint);
  if (p.flow) q.set('flow', p.flow);
  if (p.insecure === true || p.insecure === 'true') q.set('allowInsecure', '1');

  // اگر رمزنگاری خاصی تعریف شده باشد
  if (p.encryption && p.encryption !== 'none') {
    q.set('encryption', p.encryption);
  }

  return {
    kind: 'vless',
    label: 'vless',
    value: `vless://${id}@${p.server}:${p.serverPort}?${q.toString()}#${encodeURIComponent(remark)}`,
  };
}

/** لینک trojan برای رمزهای غیر UUID وقتی TLS یا reality دارد. */
export function buildTrojanFromProfile(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  const pw = String(p.password ?? '');
  if (!p.server || !p.serverPort || !pw) return null;
  if (!hasTls(p) && !p.sni) return null;
  const remark = String(item.name ?? p.remarks ?? '').trim();
  const q = new URLSearchParams();
  q.set('type', p.network || 'tcp');
  if (p.path) q.set('path', p.path);
  if (p.host) q.set('host', p.host);
  q.set('security', isReality(p) ? 'reality' : hasTls(p) ? 'tls' : 'none');
  if (p.sni) q.set('sni', p.sni);
  if (p.fingerPrint) q.set('fp', p.fingerPrint);
  if (p.alpn) q.set('alpn', p.alpn);
  if (p.insecure === true || p.insecure === 'true') q.set('allowInsecure', '1');
  return {
    kind: 'trojan',
    label: 'trojan',
    value: `trojan://${encodeURIComponent(pw)}@${p.server}:${p.serverPort}?${q.toString()}#${encodeURIComponent(remark)}`,
  };
}

/** پروکسی socks5 / http وقتی کاربر و رمز جدا دارد. */
export function buildSocksLink(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  if (!p.server || !p.serverPort) return null;
  const remark = String(item.name ?? p.remarks ?? '').trim();
  const pw = String(p.password ?? '');
  const user = p.username ? `${encodeURIComponent(String(p.username))}:${encodeURIComponent(pw)}@` : '';
  const scheme = String(p.configType ?? '') === '4' && String(p.scheme ?? '').toLowerCase() === 'http' ? 'http' : 'socks5';
  return {
    kind: 'socks',
    label: scheme,
    value: `${scheme}://${user}${p.server}:${p.serverPort}#${encodeURIComponent(remark)}`,
  };
}

/**
 * نقطهٔ تصمیم واحد. به‌جای حدس زدن از شکل رمز، از configType استفاده
 * می‌کند و فقط وقتی لینکی می‌سازد که واقعاً معتبر باشد.
 */
export function buildProfileLink(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  if (!p.server || !p.serverPort) return null;
  const type = readConfigType(p);
  const cfg = String(p.configType ?? '').trim();
  const pw = String(p.password ?? '').trim();
  const reality = isReality(p);

  // 1. socks5 / http (configType=4 یا مشخصات احراز هویت بدون UUID)
  if (cfg === '4' || type === 'socks' || (p.username && pw && !UUID_RE.test(pw))) {
    return buildSocksLink(item);
  }

  // 2. shadowsocks (configType=2 یا configType=3 یا وجود متد رمزنگاری ss)
  const method = String(p.method ?? '').trim().toLowerCase();
  const isSsMethod = Boolean(
    method &&
      (method.startsWith('2022-') ||
        method.includes('gcm') ||
        method.includes('poly1305') ||
        method.includes('cfb') ||
        method.includes('ctr') ||
        method.includes('chacha')),
  );
  if (
    cfg === '2' ||
    cfg === '3' ||
    type === 'shadowsocks' ||
    (isSsMethod && cfg !== '1' && cfg !== '5' && !UUID_RE.test(pw))
  ) {
    return buildShadowsocksLink(item);
  }

  // 3. vless (صریحاً configType=5 یا type=vless یا نشانه‌های VLESS مثل Reality/flow/encryption)
  if (
    cfg === '5' ||
    type === 'vless' ||
    reality ||
    p.publicKey ||
    p.flow ||
    p.encryption === 'none'
  ) {
    if (UUID_RE.test(pw)) {
      return buildVlessFromProfile(item);
    }
    // اگر رمز UUID نبود ولی tls دارد، ممکن است تروجان باشد
    if (hasTls(p) || p.sni) return buildTrojanFromProfile(item);
    return null;
  }

  // 4. trojan (صریحاً configType=6 یا type=trojan یا رمز غیر UUID همراه با TLS/SNI)
  if (cfg === '6' || type === 'trojan' || (pw && !UUID_RE.test(pw) && (hasTls(p) || p.sni))) {
    return buildTrojanFromProfile(item);
  }

  // 5. vmess (صریحاً configType=1 یا type=vmess)
  if (cfg === '1' || type === 'vmess') {
    if (UUID_RE.test(pw)) {
      return buildVmessLink(item);
    }
  }

  // در نهایت اگر رمز UUID بود
  if (UUID_RE.test(pw)) {
    // اگر نشانه‌های VLESS داشت
    if (p.headerType === 'http' && (p.security === 'none' || !p.security)) {
      return buildVlessFromProfile(item);
    }
    return buildVmessLink(item);
  }

  if (hasTls(p) || p.sni) {
    return buildTrojanFromProfile(item);
  }

  return null;
}
