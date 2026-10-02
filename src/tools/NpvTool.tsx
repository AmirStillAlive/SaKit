import { useState, useMemo, useEffect } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Copy,
  Download,
  FileJson,
  Github,
  Lock,
  Search,
  ShieldCheck,
  RotateCcw,
  KeyRound,
  Languages,
  Loader2,
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { FileUpload } from '../components/ui/file-upload';
import { PasswordInput } from '../components/ui/password-input';
import { Alert } from '../components/ui/alert';
import { Accordion } from '../components/ui/accordion';
import { SearchInput } from '../components/ui/search-input';
import { Badge } from '../components/ui/badge';
import { EmptyState } from '../components/ui/empty-state';
import { Tabs, TabsList, TabsTrigger } from '../components/ui/tabs';
import { useToast } from '../components/ui/toast';
import {
  buildProfileLink,
  readConfigType,
  hasTls,
  isReality,
  type BuiltLink,
} from '../lib/links';
import { cn, fa, downloadText, formatNumber } from '../lib/utils';
import { I18N, FAQ_DATA, type Lang } from '../lib/i18n';

const REPO_URL = 'https://github.com/AmirStillAlive/npv-decrypt';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function getProtoBadgeVariant(proto: string): 'brand' | 'success' | 'warning' | 'secondary' | 'default' {
  const p = proto.toLowerCase();
  if (p.includes('vless')) return 'brand';
  if (p.includes('vmess')) return 'warning';
  if (p.includes('trojan')) return 'success';
  if (p.includes('shadowsocks') || p.includes('ss')) return 'brand';
  if (p.includes('socks') || p.includes('http')) return 'secondary';
  return 'default';
}



type Entry = {
  name: string;
  address: string;
  proto: string;
  net: string;
  tls: string;
  links: BuiltLink[];
  customJson: string | null;
  json: string;
  sourceFile?: string;
};

type FileSummary = {
  fileName: string;
  blobCount: number;
  entryCount: number;
  error?: string;
};

type Result = {
  fileName: string;
  fileCount: number;
  fileSummaries: FileSummary[];
  blobCount: number;
  entries: Entry[];
  raw: string;
  notes?: string[];
};

function b64encodeUnicode(s: string): string {
  return btoa(unescape(encodeURIComponent(s)));
}

/** فایل‌نام امن برای دانلود JSON هر کانفیگ */
function safeName(s: string): string {
  return s.replace(/[\\/:*?"<>|\n\r\t]/g, '_').trim().slice(0, 80) || 'config';
}

/** ساخت لینک vless از روی outbound استاندارد v2ray */
function buildVlessLink(ob: Record<string, any>, remark: string): BuiltLink | null {
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

    return {
      kind: 'vless',
      label: 'vless',
      value: `vless://${user.id}@${vnext.address}:${vnext.port ?? 443}?${q.toString()}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/** ساخت لینک vmess از روی outbound استاندارد v2ray */
function buildVmessLinkFromOutbound(ob: Record<string, any>, remark: string): BuiltLink | null {
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
      add: vnext.address,
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

/** ساخت لینک trojan از روی outbound استاندارد v2ray */
function buildTrojanLink(ob: Record<string, any>, remark: string): BuiltLink | null {
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
    return {
      kind: 'trojan',
      label: 'trojan',
      value: `trojan://${encodeURIComponent(String(srv.password))}@${srv.address}:${srv.port ?? 443}?${q.toString()}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/** ساخت لینک http proxy از روی outbound استاندارد v2ray */
function buildHttpLink(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const st = ob.settings ?? {};
    const srv = (st.servers ?? [])[0] ?? {};
    const u = (srv.users ?? [])[0] ?? {};
    const addr = srv.address || ob.address;
    const port = srv.port || ob.port || 1080;
    if (!addr) return null;
    const auth = u.user ? `${encodeURIComponent(u.user)}:${encodeURIComponent(u.pass ?? '')}@` : '';
    return {
      kind: 'http',
      label: 'http',
      value: `http://${auth}${addr}:${port}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/** ساخت لینک socks5 proxy از روی outbound استاندارد v2ray */
function buildSocksLink(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const st = ob.settings ?? {};
    const srv = (st.servers ?? [])[0] ?? {};
    const u = (srv.users ?? [])[0] ?? {};
    const addr = srv.address || ob.address;
    const port = srv.port || ob.port || 1080;
    if (!addr) return null;
    const auth = u.user ? `${encodeURIComponent(u.user)}:${encodeURIComponent(u.pass ?? '')}@` : '';
    return {
      kind: 'socks',
      label: 'socks5',
      value: `socks5://${auth}${addr}:${port}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/** ساخت لینک shadowsocks از روی outbound استاندارد v2ray */
function buildShadowsocksLink(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const st = ob.settings ?? {};
    const srv = (st.servers ?? [])[0] ?? {};
    if (!srv.address || !srv.password || !srv.method) return null;
    const creds = btoa(`${srv.method}:${srv.password}`);
    return {
      kind: 'shadowsocks',
      label: 'ss',
      value: `ss://${creds}@${srv.address}:${srv.port ?? 8388}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/** ساخت لینک vmess برای پروفایل‌های ساده بدون v2rayJson */
function buildVmessLink(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  if (!p.password || !p.server) return null;
  const inner = {
    v: '2',
    ps: String(item.name ?? p.remarks ?? '').trim(),
    add: p.server,
    port: String(p.serverPort),
    id: p.password,
    aid: '0',
    scy: p.method && String(p.method).length < 32 ? p.method : 'auto',
    net: p.network || 'tcp',
    type: p.headerType || 'none',
    host: p.host || '',
    path: p.path || '',
    tls: p.security === 'tls' ? 'tls' : '',
    sni: p.sni || '',
    fp: p.fingerPrint || '',
    alpn: p.alpn || '',
  };
  return { kind: 'vmess', label: 'vmess', value: 'vmess://' + b64encodeUnicode(JSON.stringify(inner)) };
}

/** نوع فایل را از روی محتوا حدس می‌زند؛ متن به base64 تبدیل می‌شود. */
function detectFormat(text: string): 'npvs' | 'npvt' | 'unknown' {
  const head = text.trimStart().slice(0, 16);
  if (head.startsWith('NPVS')) return 'npvs';
  if (head.includes('NPVT1') || head.includes('NPVTSUB1')) return 'npvt';
  return 'unknown';
}

/**
 * نسخهٔ NPVS را از روی بایت پنجم فایل می‌خواند.
 * نسخهٔ ۱ پاکت با سرآیند JSON است و نسخهٔ ۵ پاکت فشردهٔ gen2؛ هر دو پشتیبانی
 * می‌شوند. نسخه‌های دیگر (۲ تا ۴ و بالاتر از ۵) چیدمان ناشناخته دارند.
 * @returns شماره نسخه، یا null اگر فایل NPVS نبود
 */
async function readNpvsVersion(file: File): Promise<number | null> {
  const buf = await file.slice(0, 5).arrayBuffer();
  const head = new Uint8Array(buf);
  const isNpvs = head.length === 5 && String.fromCharCode(...head.slice(0, 4)) === 'NPVS';
  return isNpvs ? head[4] : null;
}

function createEntryFromItem(item: Record<string, any>): Entry | null {
  if (!item || typeof item !== 'object') return null;
  // اگر آیتم فاقد تنظیمات سرور یا پروفایل باشد (مثل lockConfig)، آن را نادیده می‌گیریم
  if (!item.v2rayProfile && !item.server && !item.address) return null;

  const profile = (item.v2rayProfile ?? {}) as Record<string, any>;
  const name = String(item.name ?? profile.remarks ?? '').trim() || 'بدون نام';
  const address = String(
    profile.server ? `${profile.server}:${profile.serverPort}` : (item.address ?? 'نامشخص'),
  );
  let proto = 'نامشخص';
  let net = String(profile.network ?? 'نامشخص');
  let tls = String(profile.security ?? 'نامشخص');
  let links: BuiltLink[] = [];
  let customJson: string | null = null;

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

        const b =
          proxy.protocol === 'vless'
            ? buildVlessLink(proxy, name)
            : proxy.protocol === 'vmess'
              ? buildVmessLinkFromOutbound(proxy, name)
              : proxy.protocol === 'trojan'
                ? buildTrojanLink(proxy, name)
                : proxy.protocol === 'http'
                  ? buildHttpLink(proxy, name)
                  : proxy.protocol === 'socks'
                    ? buildSocksLink(proxy, name)
                    : proxy.protocol === 'shadowsocks'
                      ? buildShadowsocksLink(proxy, name)
                      : null;
        if (b) links.push(b);
      }
      customJson = JSON.stringify(full, null, 2);
    } catch {
      /* اگر v2rayJson قابل تفسیر نبود، از روی پروفایل ادامه می‌دهیم */
    }
  }

  if (!links.length) {
    const b = buildProfileLink(item);
    if (b) {
      links.push(b);
      proto = b.kind;
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
  };
}

/** فایل NPVS را باز می‌کند و به همان ساختار خروجی .npvt تبدیل می‌کند. */
async function decryptNpvsFile(file: File, password: string): Promise<{ result: Result; npv: any }> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const version = bytes.length > 4 ? bytes[4] : 0;

  let res: any;
  if (version === 5) {
    // نسخهٔ ۵ جدول‌های جدایی دارد؛ فقط برای همین فایل دانلود می‌شود
    const gen2 = await import('../lib/npvs_gen2');
    if (!gen2.hasGen2Tables()) await gen2.loadGen2Tables();
    res = await gen2.decryptNpvsGen2(bytes, password);
  } else {
    const [npvs, tables] = await Promise.all([
      import('../lib/npvs'),
      import('../lib/npvs_tables.json'),
    ]);
    if (!npvs.hasWbTables()) npvs.setWbTables(tables.default);
    res = await npvs.decryptNpvs(bytes, password);
  }

  // متن باز شده ممکن است یک کانفیگ، یک آرایه، یا چند کانفیگ پشت‌سرهم باشد
  const entries: Entry[] = [];
  const pushItem = (item: Record<string, any>) => {
    const entry = createEntryFromItem(item);
    if (entry) entries.push(entry);
  };

  const collect = (value: unknown) => {
    if (Array.isArray(value)) value.forEach(collect);
    else if (value && typeof value === 'object') pushItem(value as Record<string, any>);
  };

  if (res.json) {
    collect(res.json);
  } else {
    // متن آزاد: تکه‌های JSON را یکی‌یکی پیدا می‌کنیم
    for (const m of res.plaintext.match(/\{[\s\S]*?\}/g) ?? []) {
      try {
        collect(JSON.parse(m));
      } catch {
        /* تکهٔ ناقص را رد می‌کنیم */
      }
    }
  }

  // سرآیند را هم بالای خروجی می‌نویسیم تا چیزی گم نشود
  const keyLines: string[] = [];
  for (const [k, v] of res.keys as [string, string][]) {
    if (k !== 'DEK/CEK' && v) keyLines.push(`# ${k}: ${v}`);
  }
  const header = [
    `# ${file.name} : خروجی npv-decrypt`,
    `# configId: ${res.meta.configId ?? 'نامشخص'}`,
    ...res.notes.map((n: string) => `# ${n}`),
    ...keyLines,
  ].join('\n');

  return {
    npv: null,
    result: {
      fileName: file.name,
      fileCount: 1,
      fileSummaries: [
        {
          fileName: file.name,
          blobCount: entries.length,
          entryCount: entries.length,
        },
      ],
      blobCount: entries.length,
      entries,
      raw: `${header}\n\n${res.plaintext}`,
      notes: res.notes,
    },
  };
}

async function decryptSingleFile(
  file: File,
  password = '',
): Promise<{ fileName: string; blobCount: number; entries: Entry[]; raw: string; notes?: string[] }> {
  const text = await file.text();
  const fmt = detectFormat(text);

  if (fmt === 'npvs') {
    const version = await readNpvsVersion(file);
    if (version !== null && version !== 1 && version !== 5) {
      throw new Error(
        `فایل «${file.name}» نسخهٔ ${version} فرمت NPVS است و فقط نسخهٔ ۱ و ۵ پشتیبانی می‌شود.`,
      );
    }
    const dec = await decryptNpvsFile(file, password);
    return {
      fileName: file.name,
      blobCount: dec.result.blobCount,
      entries: dec.result.entries.map((e) => ({ ...e, sourceFile: file.name })),
      raw: dec.result.raw,
      notes: dec.result.notes,
    };
  }

  const [npv, tables] = await Promise.all([
    import('../lib/npv'),
    import('../lib/npv_tables.json'),
  ]);
  if (!npv.hasTables()) npv.setTables(tables.default);

  const blobs = npv.decryptFileText(text);
  if (!blobs.length) {
    throw new Error(`فایل «${file.name}» شناخته نشد. فقط فایل .npvt و .npvs معتبر است.`);
  }

  const prettyParts = blobs.map((b: Uint8Array) => npv.pretty(b));
  const entries: Entry[] = [];

  for (const part of prettyParts) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(part);
    } catch {
      continue;
    }
    const list = Array.isArray(parsed) ? parsed : [parsed];
    for (const item of list as Record<string, any>[]) {
      const entry = createEntryFromItem(item);
      if (entry) entries.push({ ...entry, sourceFile: file.name });
    }
  }

  return {
    fileName: file.name,
    blobCount: blobs.length,
    entries,
    raw: prettyParts.join('\n\n'),
  };
}

/** متن فایل «همه لینک‌ها»: هر خط یک لینک */
function allLinksText(result: Result): string {
  const lines = [`# ${result.fileName} : خروجی npv-decrypt`, ''];
  if (result.fileCount > 1) {
    lines.push(`# مجموعاً ${fa(result.fileCount)} فایل و ${fa(result.entries.length)} کانفیگ:`);
    for (const f of result.fileSummaries) {
      if (f.error) {
        lines.push(`#  - ${f.fileName} : خطا (${f.error})`);
      } else {
        lines.push(`#  - ${f.fileName} : ${fa(f.entryCount)} کانفیگ`);
      }
    }
    lines.push('');
  }
  for (const e of result.entries) {
    lines.push(`# ${e.name} (${e.address})${e.sourceFile ? ` [${e.sourceFile}]` : ''}`);
    for (const l of e.links) lines.push(l.value);
    if (e.customJson) lines.push('# کانفیگ JSON کامل را با دکمه JSON همین ردیف بگیرید');
    lines.push('');
  }
  return lines.join('\n');
}

function CopyButton({
  value,
  label,
  onCopy,
}: {
  value: string;
  label: string;
  onCopy?: () => void;
}) {
  const [done, setDone] = useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      className="shrink-0 transition-transform active:scale-95"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          onCopy?.();
        } catch {
          /* اگر مرورگر اجازه نداد، بی‌صدا رد می‌شویم */
        }
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
      aria-label={label}
    >
      {done ? <Check className="text-success" /> : <Copy />}
      {done ? 'کپی شد' : label}
    </Button>
  );
}

export interface NpvToolProps {
  lang: Lang;
}

export const NpvTool: React.FC<NpvToolProps> = ({ lang }) => {
  const { toast } = useToast();
  const t = I18N[lang];
  const isEn = lang === 'en';

  const [files, setFiles] = useState<File[]>([]);
  const [password, setPassword] = useState('');
  const [needsPassword, setNeedsPassword] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [result, setResult] = useState<Result | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedProto, setSelectedProto] = useState('all');
  const [copiedAll, setCopiedAll] = useState(false);

  const stats = useMemo(() => {
    if (!result) return null;
    const total = result.entries.length;
    const vless = result.entries.filter((e) => e.proto.toLowerCase().includes('vless')).length;
    const vmess = result.entries.filter((e) => e.proto.toLowerCase().includes('vmess')).length;
    const trojan = result.entries.filter((e) => e.proto.toLowerCase().includes('trojan')).length;
    const shadowsocks = result.entries.filter((e) => e.proto.toLowerCase().includes('shadowsocks')).length;
    const socks = result.entries.filter((e) => e.proto.toLowerCase().includes('socks')).length;
    const http = result.entries.filter((e) => e.proto.toLowerCase().includes('http')).length;
    return { total, vless, vmess, trojan, shadowsocks, socks, http };
  }, [result]);

  const availableTabs = useMemo(() => {
    if (!stats) return [];
    const num = (n: number) => (isEn ? String(n) : fa(n));
    const tabs = [{ id: 'all', label: isEn ? `All (${num(stats.total)})` : `همه (${num(stats.total)})` }];
    if (stats.vless > 0) tabs.push({ id: 'vless', label: `VLESS (${num(stats.vless)})` });
    if (stats.vmess > 0) tabs.push({ id: 'vmess', label: `VMess (${num(stats.vmess)})` });
    if (stats.trojan > 0) tabs.push({ id: 'trojan', label: `Trojan (${num(stats.trojan)})` });
    if (stats.shadowsocks > 0) tabs.push({ id: 'shadowsocks', label: `Shadowsocks (${num(stats.shadowsocks)})` });
    if (stats.socks > 0) tabs.push({ id: 'socks', label: `SOCKS5 (${num(stats.socks)})` });
    if (stats.http > 0) tabs.push({ id: 'http', label: `HTTP (${num(stats.http)})` });
    return tabs;
  }, [stats, isEn]);

  const filteredEntries = useMemo(() => {
    if (!result) return [];
    return result.entries.filter((e) => {
      const p = e.proto.toLowerCase();
      const matchProto =
        selectedProto === 'all' ||
        (selectedProto === 'vless' && p.includes('vless')) ||
        (selectedProto === 'vmess' && p.includes('vmess')) ||
        (selectedProto === 'trojan' && p.includes('trojan')) ||
        (selectedProto === 'shadowsocks' && p.includes('shadowsocks')) ||
        (selectedProto === 'socks' && p.includes('socks')) ||
        (selectedProto === 'http' && p.includes('http'));
      if (!matchProto) return false;

      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase().trim();
      return (
        e.name.toLowerCase().includes(q) ||
        e.address.toLowerCase().includes(q) ||
        e.proto.toLowerCase().includes(q) ||
        e.net.toLowerCase().includes(q) ||
        (e.sourceFile && e.sourceFile.toLowerCase().includes(q)) ||
        e.links.some((l) => l.value.toLowerCase().includes(q))
      );
    });
  }, [result, searchQuery, selectedProto]);

  const copyVisibleLinks = async () => {
    const links = filteredEntries.flatMap((e) => e.links.map((l) => l.value));
    if (!links.length) return;
    try {
      await navigator.clipboard.writeText(links.join('\n'));
      setCopiedAll(true);
      toast(t.toastAllCopied(isEn ? links.length : (fa(links.length) as any)), 'success');
      setTimeout(() => setCopiedAll(false), 2000);
    } catch {
      /* ignore */
    }
  };

  async function run() {
    if (!files.length) return;
    setBusy(true);
    setError(null);
    setWarnings([]);
    setResult(null);
    setNeedsPassword(null);
    setSearchQuery('');
    setSelectedProto('all');
    // بارگذاری جدول‌ها از حلقه رندر بیرون است
    await new Promise((r) => setTimeout(r, 30));
    try {
      const allEntries: Entry[] = [];
      const fileSummaries: FileSummary[] = [];
      const rawParts: string[] = [];
      const allNotes: string[] = [];
      let totalBlobs = 0;
      const passNeededFiles: string[] = [];
      const fileErrors: string[] = [];

      for (const f of files) {
        try {
          const dec = await decryptSingleFile(f, password);
          allEntries.push(...dec.entries);
          totalBlobs += dec.blobCount;
          rawParts.push(`// ==================== ${f.name} ====================\n${dec.raw}`);
          if (dec.notes?.length) allNotes.push(...dec.notes);
          fileSummaries.push({
            fileName: f.name,
            blobCount: dec.blobCount,
            entryCount: dec.entries.length,
          });
        } catch (e: any) {
          if (e?.name === 'NeedsPassphrase') {
            passNeededFiles.push(f.name);
            fileSummaries.push({
              fileName: f.name,
              blobCount: 0,
              entryCount: 0,
            });
          } else {
            const msg = e instanceof Error ? e.message : 'خطای رمزگشایی';
            fileErrors.push(`«${f.name}»: ${msg}`);
            fileSummaries.push({
              fileName: f.name,
              blobCount: 0,
              entryCount: 0,
              error: msg,
            });
          }
        }
      }

      if (passNeededFiles.length > 0) {
        setNeedsPassword(
          passNeededFiles.length === 1
            ? `فایل «${passNeededFiles[0]}» دارای رمز عبور است. لطفاً رمز را وارد کنید.`
            : `فایل‌های «${passNeededFiles.join('»، «')}» دارای رمز عبور هستند. لطفاً رمز را وارد کنید.`,
        );
      }

      if (fileErrors.length > 0) {
        if (allEntries.length === 0 && passNeededFiles.length === 0) {
          setError(fileErrors.join('\n'));
          return;
        } else {
          setWarnings(fileErrors);
        }
      }

      if (allEntries.length === 0) {
        // فایلی باز نشد (یا منتظر دریافت رمز است)
        return;
      }

      const displayName =
        files.length === 1 ? files[0].name : (isEn ? `${files.length} files` : `${fa(files.length)} فایل`);

      setResult({
        fileName: displayName,
        fileCount: files.length,
        fileSummaries,
        blobCount: totalBlobs,
        entries: allEntries,
        raw: rawParts.join('\n\n'),
        notes: allNotes,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : (isEn ? 'Decryption failed.' : 'رمزگشایی ناموفق بود.'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="w-full max-w-4xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* سربرگ */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-sm">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>{t.badge}</span>
        </div>
        <h1 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-foreground">
          {t.title}
        </h1>
        <p className="text-sm sm:text-base text-muted-foreground max-w-xl mx-auto leading-relaxed">
          {t.subtitle}
        </p>
      </div>

      {/* ابزار */}
      <section className="rounded-surface border border-border bg-card p-5 shadow-surface">
        <div className="space-y-4">
          <FileUpload
            accept=".npvt,.npvs"
            multiple={true}
            maxSize={10 * 1024 * 1024}
            onFiles={setFiles}
            lang={lang}
            hint={t.uploadHintDefault}
          />
          <div className="flex items-center gap-3">
            <Button onClick={run} disabled={files.length === 0 || busy}>
              {busy
                ? t.btnDecrypting
                : files.length > 1
                  ? t.btnDecryptMultiple(isEn ? files.length : (fa(files.length) as any))
                  : t.btnDecrypt}
              {!busy && (isEn ? <ArrowRight className="size-4" /> : <ArrowLeft className="size-4" />)}
            </Button>
            {busy && (
              <span className="text-xs text-muted-foreground">{t.btnLoadingTables}</span>
            )}
          </div>
          {needsPassword && (
            <div className="space-y-3.5 rounded-xl border border-warning/35 bg-warning/5 p-4 shadow-sm transition-all duration-300 animate-in fade-in slide-in-from-top-3">
              <Alert variant="warning" title={t.passAlertTitle}>
                {needsPassword}
              </Alert>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
                <div className="min-w-0 flex-1">
                  <PasswordInput
                    id="npvs-password"
                    label={t.passLabel}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && password.trim() && run()}
                    placeholder={t.passPlaceholder}
                    hint={t.passHint}
                    autoFocus
                  />
                </div>
                <Button
                  type="button"
                  onClick={run}
                  disabled={!password.trim() || busy}
                  className="h-10 w-full sm:w-auto shrink-0 font-medium transition-all duration-200 active:scale-95 shadow-sm"
                >
                  <KeyRound className="size-4" />
                  <span>{busy ? t.btnDecrypting : t.passConfirm}</span>
                  {!busy && (isEn ? <ArrowRight className="size-4" /> : <ArrowLeft className="size-4" />)}
                </Button>
              </div>
            </div>
          )}
          {warnings.length > 0 && (
            <Alert variant="warning" title={isEn ? 'Some files could not be opened' : 'برخی فایل‌ها باز نشدند'}>
              <ul className="list-disc pe-4 space-y-1 text-xs">
                {warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </Alert>
          )}
          {error && (
            <Alert variant="destructive" title={isEn ? 'Error' : 'خطا'}>
              {error}
            </Alert>
          )}
        </div>

        {/* نتیجه */}
        {result && (
          <div className="mt-6 space-y-5 border-t border-border pt-5 transition-all duration-300 animate-in fade-in slide-in-from-bottom-3">
            {/* سربرگ نتیجه و اکشن‌ها */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
                  <Badge variant="success">{isEn ? 'Decrypted' : 'رمزگشایی موفق'}</Badge>
                  <span dir="ltr" className="font-mono text-sm text-muted-foreground">{result.fileName}</span>
                </h2>
                <p className={cn('mt-1 text-xs text-muted-foreground', !isEn && 'fa-num')}>
                  {isEn
                    ? `${result.fileCount > 1 ? `${result.fileCount} files — ` : ''}${result.blobCount} data blocks, ${result.entries.length} configs extracted.`
                    : `${result.fileCount > 1 ? `مجموعاً ${fa(result.fileCount)} فایل، ` : ''}${fa(result.blobCount)} بلاک داده و ${fa(result.entries.length)} کانفیگ استخراج شد.`}
                </p>
                {result.notes && result.notes.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {result.notes.map((n, i) => (
                      <span
                        key={i}
                        className="inline-flex items-center rounded-md border border-border/70 bg-muted/40 px-2 py-0.5 text-[11px] text-muted-foreground"
                      >
                        {n}
                      </span>
                    ))}
                  </div>
                )}
                {stats && stats.total > 1 && (
                  <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                    <span className="text-[11px] text-muted-foreground">{isEn ? 'Filter:' : 'دسته‌بندی:'}</span>
                    {stats.vless > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelectedProto(selectedProto === 'vless' ? 'all' : 'vless')}
                        className="cursor-pointer transition-transform active:scale-95"
                        title={isEn ? 'Filter VLESS' : 'فیلتر VLESS'}
                      >
                        <Badge variant={selectedProto === 'vless' ? 'brand' : 'outline'} className="text-[11px] hover:border-brand">
                          VLESS: {isEn ? stats.vless : fa(stats.vless)}
                        </Badge>
                      </button>
                    )}
                    {stats.vmess > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelectedProto(selectedProto === 'vmess' ? 'all' : 'vmess')}
                        className="cursor-pointer transition-transform active:scale-95"
                        title={isEn ? 'Filter VMess' : 'فیلتر VMess'}
                      >
                        <Badge variant={selectedProto === 'vmess' ? 'warning' : 'outline'} className="text-[11px] hover:border-warning">
                          VMess: {isEn ? stats.vmess : fa(stats.vmess)}
                        </Badge>
                      </button>
                    )}
                    {stats.trojan > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelectedProto(selectedProto === 'trojan' ? 'all' : 'trojan')}
                        className="cursor-pointer transition-transform active:scale-95"
                        title={isEn ? 'Filter Trojan' : 'فیلتر Trojan'}
                      >
                        <Badge variant={selectedProto === 'trojan' ? 'success' : 'outline'} className="text-[11px] hover:border-success">
                          Trojan: {isEn ? stats.trojan : fa(stats.trojan)}
                        </Badge>
                      </button>
                    )}
                    {stats.shadowsocks > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelectedProto(selectedProto === 'shadowsocks' ? 'all' : 'shadowsocks')}
                        className="cursor-pointer transition-transform active:scale-95"
                        title={isEn ? 'Filter Shadowsocks' : 'فیلتر Shadowsocks'}
                      >
                        <Badge variant={selectedProto === 'shadowsocks' ? 'brand' : 'outline'} className="text-[11px] hover:border-brand">
                          Shadowsocks: {isEn ? stats.shadowsocks : fa(stats.shadowsocks)}
                        </Badge>
                      </button>
                    )}
                    {stats.socks > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelectedProto(selectedProto === 'socks' ? 'all' : 'socks')}
                        className="cursor-pointer transition-transform active:scale-95"
                        title={isEn ? 'Filter SOCKS5' : 'فیلتر SOCKS5'}
                      >
                        <Badge variant={selectedProto === 'socks' ? 'secondary' : 'outline'} className="text-[11px]">
                          SOCKS5: {isEn ? stats.socks : fa(stats.socks)}
                        </Badge>
                      </button>
                    )}
                    {stats.http > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelectedProto(selectedProto === 'http' ? 'all' : 'http')}
                        className="cursor-pointer transition-transform active:scale-95"
                        title={isEn ? 'Filter HTTP' : 'فیلتر HTTP'}
                      >
                        <Badge variant={selectedProto === 'http' ? 'secondary' : 'outline'} className="text-[11px]">
                          HTTP: {isEn ? stats.http : fa(stats.http)}
                        </Badge>
                      </button>
                    )}
                  </div>
                )}
              </div>

              {/* اکشن‌های کپی همگانی و دانلود */}
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={copyVisibleLinks}
                  disabled={filteredEntries.length === 0}
                  title={isEn ? 'Copy all links in current view' : 'کپی لینک‌های تمام کانفیگ‌های لیست فعلی'}
                >
                  {copiedAll ? <Check className="text-success" /> : <Copy />}
                  {copiedAll ? t.copied : `${isEn ? 'Copy all' : 'کپی همه'} (${isEn ? filteredEntries.length : fa(filteredEntries.length)})`}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    downloadText(
                      (result.fileCount > 1 ? 'npv-all-links' : result.fileName.replace(/\.(npvt|npvs)$/i, '')) + '-links.txt',
                      allLinksText(result),
                    );
                    toast(isEn ? 'Links text file downloaded' : 'فایل متنی لینک‌ها دانلود شد', 'info');
                  }}
                >
                  <Download />
                  {t.downloadAllLinks}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    downloadText(
                      (result.fileCount > 1 ? 'npv-all-raw' : result.fileName.replace(/\.(npvt|npvs)$/i, '')) + '.txt',
                      result.raw,
                    );
                    toast(isEn ? 'Raw JSON file downloaded' : 'فایل JSON خام دانلود شد', 'info');
                  }}
                >
                  <Download />
                  {t.downloadRawJson}
                </Button>
              </div>
            </div>

            {/* نوار جست‌وجو و فیلترهای وایب‌فارسی */}
            {result.entries.length > 1 && (
              <div className="space-y-3 rounded-xl border border-border/60 bg-muted/20 p-3">
                <SearchInput
                  value={searchQuery}
                  onChange={setSearchQuery}
                  placeholder={t.searchPlaceholder}
                />
                {availableTabs.length > 2 && (
                  <Tabs value={selectedProto} defaultValue="all" onValueChange={setSelectedProto}>
                    <TabsList aria-label={isEn ? 'Protocol filter' : 'فیلتر پروتکل'}>
                      {availableTabs.map((tab) => (
                        <TabsTrigger key={tab.id} value={tab.id}>
                          {tab.label}
                        </TabsTrigger>
                      ))}
                    </TabsList>
                  </Tabs>
                )}
              </div>
            )}

            {/* لیست کانفیگ‌ها یا حالت خالی */}
            {filteredEntries.length > 0 ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between px-1 text-xs text-muted-foreground">
                  <span className={cn(!isEn && 'fa-num')}>
                    {isEn
                      ? `Showing ${filteredEntries.length} of ${result.entries.length} configs`
                      : `نمایش ${fa(filteredEntries.length)} از ${fa(result.entries.length)} کانفیگ`}
                  </span>
                  {(searchQuery || selectedProto !== 'all') && (
                    <button
                      type="button"
                      onClick={() => {
                        setSearchQuery('');
                        setSelectedProto('all');
                      }}
                      className="inline-flex cursor-pointer items-center gap-1 text-brand hover:underline"
                    >
                      <RotateCcw className="size-3" />
                      {t.clearFilters}
                    </button>
                  )}
                </div>

                <ul className="divide-y divide-border/60 overflow-hidden rounded-xl border border-border/80 bg-card">
                  {filteredEntries.map((e, i) => (
                    <li key={i} className="space-y-3 p-4 transition-colors hover:bg-muted/10">
                      {/* سربرگ کارت: نام، آدرس و بج‌های وایب‌فارسی */}
                      <div className="flex flex-col gap-1.5 sm:flex-row sm:items-start sm:justify-between">
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="truncate text-sm font-semibold text-foreground" dir="auto" title={e.name}>
                              {e.name}
                            </p>
                            {result.fileCount > 1 && e.sourceFile && (
                              <Badge
                                variant="secondary"
                                className="max-w-[160px] truncate text-[10px] text-muted-foreground"
                                title={e.sourceFile}
                              >
                                {e.sourceFile}
                              </Badge>
                            )}
                          </div>
                          <p className="mt-0.5 text-xs text-muted-foreground fa-num">
                            <span dir="ltr" className="font-mono text-muted-foreground">{e.address}</span>
                          </p>
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Badge variant={getProtoBadgeVariant(e.proto)}>
                            {e.proto.toUpperCase()}
                          </Badge>
                          {e.net && (
                            <Badge variant="outline">
                              {e.net.toUpperCase()}
                            </Badge>
                          )}
                          {e.tls && e.tls !== 'نامشخص' && (
                            <Badge variant="success">
                              <ShieldCheck className="inline-block size-3" />
                              {e.tls.toUpperCase()}
                            </Badge>
                          )}
                        </div>
                      </div>

                      {/* لینک‌های قابل استفاده */}
                      {e.links.length > 0 ? (
                        <div className="space-y-2">
                          {e.links.map((l, j) => (
                            <div key={j} className="flex items-center gap-2">
                              <Badge variant="brand" className="px-1.5 py-0.5 font-mono text-[11px] uppercase">
                                {l.label}
                              </Badge>
                              <code
                                dir="ltr"
                                className="min-w-0 flex-1 select-all truncate rounded border border-border/50 bg-background/80 px-2.5 py-1 font-mono text-[11px] text-muted-foreground hover:text-foreground"
                              >
                                {l.value}
                              </code>
                              <CopyButton
                                value={l.value}
                                label={isEn ? `Copy ${l.label}` : `کپی ${l.label}`}
                                onCopy={() => toast(t.toastLinkCopied(l.label), 'success')}
                              />
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-warning">{t.noLinkReady}</p>
                      )}

                      {/* دکمه‌های JSON */}
                      <div className="flex flex-wrap items-center gap-2 border-t border-border/30 pt-1">
                        {e.customJson && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              downloadText(`${safeName(e.name)}.json`, e.customJson!);
                              toast(t.toastJsonDownloaded(e.name), 'info');
                            }}
                          >
                            <FileJson />
                            {t.downloadJson}
                          </Button>
                        )}
                        <details className="w-full">
                          <summary className="cursor-pointer select-none text-xs text-muted-foreground hover:text-foreground">
                            {t.showFullJson}
                          </summary>
                          <pre
                            dir="ltr"
                            className="mt-2 max-h-64 overflow-auto rounded-lg border border-border/60 bg-background/90 p-3 font-mono text-xs leading-relaxed"
                          >
                            {e.json}
                          </pre>
                        </details>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <EmptyState
                icon={Search}
                title={t.emptySearchTitle}
                description={t.emptySearchDesc}
                action={
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setSearchQuery('');
                      setSelectedProto('all');
                    }}
                  >
                    <RotateCcw className="size-3.5" />
                    {t.clearFilters}
                  </Button>
                }
              />
            )}
          </div>
        )}
      </section>

      {/* پرسش‌های پرتکرار */}
      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-muted-foreground">{t.faqTitle}</h2>
        <Accordion items={FAQ_DATA[lang]} />
      </section>
    </div>
  );
};
