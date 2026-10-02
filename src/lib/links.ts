/**
 * Consolidated link serialization and configuration normalization.
 *
 * This module is the single source of truth for:
 * - Detecting protocol types (Shadowsocks, VLESS, VMess, Trojan, SOCKS5, HTTP)
 * - Constructing protocol URIs according to official specifications:
 *   - SIP002 for Shadowsocks
 *   - VLESS URI format with Reality and TLS parameter support
 *   - VMess v2 JSON format
 *   - Trojan URI specification
 *   - RFC 3986 URI host bracket formatting for IPv6 addresses
 * - Transforming decrypted profile objects or standard v2ray outbounds into uniform UI entries.
 */

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type ProtocolKind = 'vmess' | 'vless' | 'trojan' | 'http' | 'socks' | 'shadowsocks';

export type ConfigType = 'shadowsocks' | 'vless' | 'vmess' | 'trojan' | 'socks' | 'unknown';

export type BuiltLink = {
  kind: ProtocolKind;
  label: string;
  value: string;
};

export type Entry = {
  name: string;
  address: string;
  proto: string;
  net: string;
  tls: string;
  links: BuiltLink[];
  customJson: string | null;
  json: string;
  notes?: string[];
  sourceFile?: string;
};

/**
 * Encodes a UTF-8 string into standard Base64.
 */
export function b64encodeUnicode(s: string): string {
  return btoa(unescape(encodeURIComponent(s)));
}

/**
 * Formats host and port according to RFC 3986.
 * IPv6 addresses containing colons are enclosed in square brackets: [2001:db8::1]:443
 */
export function formatHostPort(host: string, port?: string | number): string {
  const h = String(host || '').trim();
  const p = port !== undefined && port !== null ? String(port).trim() : '';
  if (!h) return '';
  const bracketed = h.includes(':') && !h.startsWith('[') ? `[${h}]` : h;
  return p ? `${bracketed}:${p}` : bracketed;
}

/**
 * Normalizes host representation for JSON fields (e.g. VMess inner add).
 * Strips outer brackets if present on an IPv6 address.
 */
export function unbracketHost(host: string): string {
  const h = String(host || '').trim();
  if (h.startsWith('[') && h.endsWith(']')) {
    return h.slice(1, -1);
  }
  return h;
}

/**
 * Checks if the configuration has TLS enabled.
 * Note: Reality transport implies TLS.
 */
export function hasTls(p: Record<string, any>): boolean {
  const s = String(p.security ?? '').toLowerCase();
  return s === 'tls' || s === 'reality';
}

/**
 * Checks if Reality security protocol is configured.
 */
export function isReality(p: Record<string, any>): boolean {
  return String(p.security ?? '').toLowerCase() === 'reality';
}

/**
 * Tolerantly detects the target protocol from profile attributes.
 */
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

/* ==================================================================== *
 * 1. Profile-based Link Generators (v2rayProfile)
 * ==================================================================== */

/**
 * Builds a Shadowsocks SIP002 URI from a profile.
 * Format: ss://base64(method:password)@host:port#name
 */
export function buildShadowsocksFromProfile(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  if (!p.server || !p.serverPort) return null;

  const remark = String(item.name ?? p.remarks ?? '').trim();
  const method = String(p.method ?? '').trim();
  let userInfo: string;

  if (method && method.includes(':')) {
    userInfo = method;
  } else if (method && p.password) {
    userInfo = `${method}:${p.password}`;
  } else if (p.password) {
    userInfo = String(p.password);
  } else {
    return null;
  }

  const user = b64encodeUnicode(userInfo);
  const endpoint = formatHostPort(p.server, p.serverPort);
  return {
    kind: 'shadowsocks',
    label: 'شادوساکس',
    value: `ss://${user}@${endpoint}#${encodeURIComponent(remark)}`,
  };
}

/**
 * Builds a VMess URI from a profile.
 * Only generated when the password field is a valid UUID to avoid invalid configurations.
 */
export function buildVmessFromProfile(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  const id = String(p.password ?? '');
  if (!p.server || !UUID_RE.test(id)) return null;

  const inner = {
    v: '2',
    ps: String(item.name ?? p.remarks ?? '').trim(),
    add: unbracketHost(p.server),
    port: String(p.serverPort),
    id,
    aid: String(p.alterId ?? '0'),
    scy: p.method && String(p.method).length < 32 ? p.method : 'auto',
    net: p.network || 'tcp',
    type: p.headerType || 'none',
    host: p.host || '',
    path: p.path || '',
    tls: hasTls(p) ? 'tls' : '',
    sni: p.sni || '',
    fp: p.fingerPrint || '',
    alpn: p.alpn || '',
  };

  return {
    kind: 'vmess',
    label: 'vmess',
    value: 'vmess://' + b64encodeUnicode(JSON.stringify(inner)),
  };
}

/**
 * Builds a VLESS URI from a profile.
 */
export function buildVlessFromProfile(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  const id = String(p.password ?? '');
  if (!p.server || !p.serverPort || !UUID_RE.test(id)) return null;

  const remark = String(item.name ?? p.remarks ?? '').trim();
  const reality = isReality(p);
  const q = new URLSearchParams();

  const sec = reality ? 'reality' : hasTls(p) ? 'tls' : (p.security || 'none');
  q.set('security', sec);

  const net = p.network || 'tcp';
  q.set('type', net);

  if (p.headerType && p.headerType !== 'none') {
    q.set('headerType', p.headerType);
  }

  if (p.host) q.set('host', p.host);
  if (p.path) q.set('path', p.path);

  if (reality) {
    if (p.publicKey) q.set('pbk', p.publicKey);
    if (p.shortId) q.set('sid', p.shortId);
    if (p.fingerPrint) q.set('fp', p.fingerPrint);
    if (p.spiderX) q.set('spx', p.spiderX);
  }

  if (p.sni) q.set('sni', p.sni);
  if (p.alpn) q.set('alpn', p.alpn);
  if (p.fingerPrint && !reality) q.set('fp', p.fingerPrint);
  if (p.flow) q.set('flow', p.flow);
  if (p.insecure === true || p.insecure === 'true') q.set('allowInsecure', '1');

  if (p.encryption && p.encryption !== 'none') {
    q.set('encryption', p.encryption);
  }

  const endpoint = formatHostPort(p.server, p.serverPort);
  return {
    kind: 'vless',
    label: 'vless',
    value: `vless://${id}@${endpoint}?${q.toString()}#${encodeURIComponent(remark)}`,
  };
}

/**
 * Builds a Trojan URI from a profile.
 */
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

  const endpoint = formatHostPort(p.server, p.serverPort);
  return {
    kind: 'trojan',
    label: 'trojan',
    value: `trojan://${encodeURIComponent(pw)}@${endpoint}?${q.toString()}#${encodeURIComponent(remark)}`,
  };
}

/**
 * Builds a SOCKS5 or HTTP proxy link from a profile.
 */
export function buildSocksFromProfile(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  if (!p.server || !p.serverPort) return null;

  const remark = String(item.name ?? p.remarks ?? '').trim();
  const pw = String(p.password ?? '');
  const user = p.username ? `${encodeURIComponent(String(p.username))}:${encodeURIComponent(pw)}@` : '';
  const scheme = String(p.configType ?? '') === '4' && String(p.scheme ?? '').toLowerCase() === 'http' ? 'http' : 'socks5';
  const endpoint = formatHostPort(p.server, p.serverPort);

  return {
    kind: 'socks',
    label: scheme,
    value: `${scheme}://${user}${endpoint}#${encodeURIComponent(remark)}`,
  };
}

/**
 * Decides and builds the most suitable link for a profile-based item.
 */
export function buildProfileLink(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  if (!p.server || !p.serverPort) return null;

  const type = readConfigType(p);
  const cfg = String(p.configType ?? '').trim();
  const pw = String(p.password ?? '').trim();
  const reality = isReality(p);

  // 1. SOCKS5 / HTTP
  if (cfg === '4' || type === 'socks' || (p.username && pw && !UUID_RE.test(pw))) {
    return buildSocksFromProfile(item);
  }

  // 2. Shadowsocks
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
    return buildShadowsocksFromProfile(item);
  }

  // 3. VLESS
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
    if (hasTls(p) || p.sni) return buildTrojanFromProfile(item);
    return null;
  }

  // 4. Trojan
  if (cfg === '6' || type === 'trojan' || (pw && !UUID_RE.test(pw) && (hasTls(p) || p.sni))) {
    return buildTrojanFromProfile(item);
  }

  // 5. VMess
  if (cfg === '1' || type === 'vmess') {
    if (UUID_RE.test(pw)) {
      return buildVmessFromProfile(item);
    }
  }

  // Fallback UUID checks
  if (UUID_RE.test(pw)) {
    if (p.headerType === 'http' && (p.security === 'none' || !p.security)) {
      return buildVlessFromProfile(item);
    }
    return buildVmessFromProfile(item);
  }

  if (hasTls(p) || p.sni) {
    return buildTrojanFromProfile(item);
  }

  return null;
}

// Backward-compatible aliases
export const buildShadowsocksLink = buildShadowsocksFromProfile;
export const buildVmessLink = buildVmessFromProfile;
export const buildSocksLink = buildSocksFromProfile;

/* ==================================================================== *
 * 2. Outbound-based Link Generators (Standard v2ray JSON outbounds)
 * ==================================================================== */

/**
 * Builds a VLESS link from a standard v2ray outbound configuration object.
 */
export function buildVlessFromOutbound(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const ss = ob.streamSettings ?? {};
    const st = ob.settings ?? {};
    const vnext = (st.vnext ?? [])[0] ?? {};
    const user = (vnext.users ?? [])[0] ?? {};
    if (!user.id || !vnext.address) return null;

    const net = ss.network ?? 'tcp';
    const sec = ss.security ?? 'none';
    const tls = ss.tlsSettings ?? {};
    const q = new URLSearchParams();
    q.set('encryption', user.encryption ?? 'none');

    if (sec === 'reality') {
      const reality = ss.realitySettings ?? {};
      q.set('security', 'reality');
      if (reality.serverName || tls.serverName) q.set('sni', reality.serverName || tls.serverName);
      if (reality.fingerprint || tls.fingerprint) q.set('fp', reality.fingerprint || tls.fingerprint);
      if (reality.publicKey) q.set('pbk', reality.publicKey);
      if (reality.shortId) q.set('sid', reality.shortId);
      if (reality.spiderX) q.set('spx', reality.spiderX);
      if (user.flow) q.set('flow', user.flow);
    } else {
      q.set('security', sec === 'tls' ? 'tls' : 'none');
      if (sec === 'tls') {
        if (tls.serverName) q.set('sni', tls.serverName);
        if (tls.fingerprint) q.set('fp', tls.fingerprint);
        const alpn = Array.isArray(tls.alpn) ? tls.alpn.join(',') : tls.alpn;
        if (alpn) q.set('alpn', alpn);
        if (tls.allowInsecure) q.set('allowInsecure', '1');
      }
    }

    if (net === 'ws') {
      const w = ss.wsSettings ?? {};
      q.set('type', 'ws');
      if (w.path) q.set('path', w.path);
      const host = (w.headers && w.headers.Host) || tls.serverName || '';
      if (host) q.set('host', host);
    } else if (net === 'xhttp') {
      const x = ss.xhttpSettings ?? {};
      q.set('type', 'xhttp');
      if (x.path) q.set('path', x.path);
      if (x.host) q.set('host', x.host);
      if (x.mode) q.set('mode', x.mode);
    } else if (net === 'tcp') {
      q.set('type', 'tcp');
      const t = ss.tcpSettings ?? {};
      const header = t.header ?? {};
      if (header.type && header.type !== 'none') q.set('headerType', header.type);
      const host = header.request?.headers?.Host;
      if (host) {
        q.set('host', Array.isArray(host) ? host.join(',') : String(host));
      }
    } else {
      q.set('type', net);
    }

    const endpoint = formatHostPort(vnext.address, vnext.port ?? 443);
    return {
      kind: 'vless',
      label: 'vless',
      value: `vless://${user.id}@${endpoint}?${q.toString()}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/**
 * Builds a VMess link from a standard v2ray outbound configuration object.
 */
export function buildVmessFromOutbound(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const ss = ob.streamSettings ?? {};
    const st = ob.settings ?? {};
    const vnext = (st.vnext ?? [])[0] ?? {};
    const user = (vnext.users ?? [])[0] ?? {};
    if (!user.id || !vnext.address) return null;

    const net = ss.network ?? 'tcp';
    const sec = ss.security ?? 'none';
    const tls = ss.tlsSettings ?? {};
    const ws = ss.wsSettings ?? {};
    const tcp = ss.tcpSettings ?? {};
    const header = tcp.header ?? {};
    const host =
      (ws.headers && ws.headers.Host) ||
      (header.request?.headers?.Host
        ? Array.isArray(header.request.headers.Host)
          ? header.request.headers.Host.join(',')
          : String(header.request.headers.Host)
        : '') ||
      tls.serverName ||
      '';

    const inner = {
      v: '2',
      ps: remark,
      add: unbracketHost(vnext.address),
      port: String(vnext.port ?? 443),
      id: user.id,
      aid: String(user.alterId ?? 0),
      scy: user.security || 'auto',
      net,
      type: header.type || 'none',
      host,
      path: ws.path || '',
      tls: sec === 'tls' ? 'tls' : '',
      sni: tls.serverName || '',
      fp: tls.fingerprint || '',
      alpn: Array.isArray(tls.alpn) ? tls.alpn.join(',') : tls.alpn || '',
    };

    return {
      kind: 'vmess',
      label: 'vmess',
      value: 'vmess://' + b64encodeUnicode(JSON.stringify(inner)),
    };
  } catch {
    return null;
  }
}

/**
 * Builds a Trojan link from a standard v2ray outbound configuration object.
 */
export function buildTrojanFromOutbound(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const ss = ob.streamSettings ?? {};
    const st = ob.settings ?? {};
    const srv = (st.servers ?? [])[0] ?? {};
    if (!srv.password || !srv.address) return null;

    const net = ss.network ?? 'tcp';
    const sec = ss.security ?? 'none';
    const tls = ss.tlsSettings ?? {};
    const q = new URLSearchParams();

    if (net === 'ws') {
      const w = ss.wsSettings ?? {};
      q.set('type', 'ws');
      if (w.path) q.set('path', w.path);
      const host = (w.headers && w.headers.Host) || '';
      if (host) q.set('host', host);
    } else {
      q.set('type', net);
    }

    q.set('security', sec === 'tls' ? 'tls' : 'none');
    if (sec === 'tls') {
      if (tls.serverName) q.set('sni', tls.serverName);
      if (tls.fingerprint) q.set('fp', tls.fingerprint);
      const alpn = Array.isArray(tls.alpn) ? tls.alpn.join(',') : tls.alpn;
      if (alpn) q.set('alpn', alpn);
      if (tls.allowInsecure) q.set('allowInsecure', '1');
    }

    const endpoint = formatHostPort(srv.address, srv.port ?? 443);
    return {
      kind: 'trojan',
      label: 'trojan',
      value: `trojan://${encodeURIComponent(String(srv.password))}@${endpoint}?${q.toString()}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/**
 * Builds an HTTP proxy link from a standard v2ray outbound configuration object.
 */
export function buildHttpFromOutbound(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const st = ob.settings ?? {};
    const srv = (st.servers ?? [])[0] ?? {};
    const u = (srv.users ?? [])[0] ?? {};
    const addr = srv.address || ob.address;
    const port = srv.port || ob.port || 1080;
    if (!addr) return null;

    const auth = u.user ? `${encodeURIComponent(u.user)}:${encodeURIComponent(u.pass ?? '')}@` : '';
    const endpoint = formatHostPort(addr, port);
    return {
      kind: 'http',
      label: 'http',
      value: `http://${auth}${endpoint}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/**
 * Builds a SOCKS5 proxy link from a standard v2ray outbound configuration object.
 */
export function buildSocksFromOutbound(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const st = ob.settings ?? {};
    const srv = (st.servers ?? [])[0] ?? {};
    const u = (srv.users ?? [])[0] ?? {};
    const addr = srv.address || ob.address;
    const port = srv.port || ob.port || 1080;
    if (!addr) return null;

    const auth = u.user ? `${encodeURIComponent(u.user)}:${encodeURIComponent(u.pass ?? '')}@` : '';
    const endpoint = formatHostPort(addr, port);
    return {
      kind: 'socks',
      label: 'socks5',
      value: `socks5://${auth}${endpoint}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/**
 * Builds a Shadowsocks link from a standard v2ray outbound configuration object.
 */
export function buildShadowsocksFromOutbound(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const st = ob.settings ?? {};
    const srv = (st.servers ?? [])[0] ?? {};
    if (!srv.address || !srv.password || !srv.method) return null;

    const creds = b64encodeUnicode(`${srv.method}:${srv.password}`);
    const endpoint = formatHostPort(srv.address, srv.port ?? 8388);
    return {
      kind: 'shadowsocks',
      label: 'ss',
      value: `ss://${creds}@${endpoint}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/**
 * Builds a link from any standard v2ray outbound object based on its protocol.
 */
export function buildLinkFromOutbound(ob: Record<string, any>, remark: string): BuiltLink | null {
  const proto = String(ob.protocol ?? '').toLowerCase();
  switch (proto) {
    case 'vless':
      return buildVlessFromOutbound(ob, remark);
    case 'vmess':
      return buildVmessFromOutbound(ob, remark);
    case 'trojan':
      return buildTrojanFromOutbound(ob, remark);
    case 'http':
      return buildHttpFromOutbound(ob, remark);
    case 'socks':
      return buildSocksFromOutbound(ob, remark);
    case 'shadowsocks':
      return buildShadowsocksFromOutbound(ob, remark);
    default:
      return null;
  }
}

/* ==================================================================== *
 * 3. Unified Entry Transformation
 * ==================================================================== */

/**
 * Transforms a raw configuration item (from NPV/NPVS decryption or JSON)
 * into a standardized Entry record for display in the UI.
 */
export function createEntryFromItem(item: Record<string, any>, sourceFile?: string): Entry | null {
  if (!item || typeof item !== 'object') return null;

  // Ignore configuration entries that lack server/profile definitions (e.g. lockConfig metadata)
  if (!item.v2rayProfile && !item.server && !item.address) return null;

  const profile = (item.v2rayProfile ?? {}) as Record<string, any>;
  const name = String(item.name ?? profile.remarks ?? '').trim() || 'بدون نام';
  const address = String(
    profile.server
      ? formatHostPort(profile.server, profile.serverPort)
      : (item.address ?? 'نامشخص'),
  );

  let proto = 'نامشخص';
  let net = String(profile.network ?? 'نامشخص');
  let tls = String(profile.security ?? 'نامشخص');
  const links: BuiltLink[] = [];
  let customJson: string | null = null;

  // 1. First priority: Check embedded v2rayJson (standard full v2ray configuration)
  if (profile.v2rayJson) {
    try {
      const full =
        typeof profile.v2rayJson === 'string'
          ? JSON.parse(profile.v2rayJson)
          : profile.v2rayJson;
      const outs = (full?.outbounds ?? []) as Record<string, any>[];
      const proxy = outs.find((o) => o.tag === 'proxy') ?? outs[0];

      if (proxy) {
        proto = String(proxy.protocol ?? 'نامشخص');
        const ss = proxy.streamSettings ?? {};
        if (ss.network) net = String(ss.network);
        if (ss.security) tls = String(ss.security);

        const link = buildLinkFromOutbound(proxy, name);
        if (link) links.push(link);
      }
      customJson = JSON.stringify(full, null, 2);
    } catch {
      // In case v2rayJson fails parsing, fall back to profile-level extraction below
    }
  }

  // 2. Second priority: If no links built from v2rayJson, build from profile
  if (!links.length) {
    const link = buildProfileLink(item);
    if (link) {
      links.push(link);
      proto = link.kind;
      if (proto === 'vless') {
        if (profile.security === 'reality' || profile.publicKey) {
          tls = 'reality';
        } else if (profile.security) {
          tls = String(profile.security);
        }
      }
      if (proto === 'shadowsocks' && (net === 'نامشخص' || !profile.network)) {
        net = 'tcp';
      }
    }
  }

  return {
    name,
    address,
    proto,
    net,
    tls,
    links,
    customJson,
    json: JSON.stringify(item, null, 2),
    ...(sourceFile ? { sourceFile } : {}),
  };
}
