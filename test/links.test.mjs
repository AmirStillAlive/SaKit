/**
 * Regression tests for the link builders.
 *
 * Validates protocol link generation across Shadowsocks (including 2022),
 * VMess, VLESS (including REALITY), and Trojan configurations.
 *
 * Run: node test/links.test.mjs
 */

import {
  buildProfileLink,
  buildShadowsocksLink,
  readConfigType,
  hasTls,
  isReality,
  formatHostPort,
  unbracketHost,
  buildLinkFromOutbound,
  createEntryFromItem,
} from '../src/lib/links.ts';

let pass = 0;
let fail = 0;
const failures = [];

function check(name, cond, detail) {
  if (cond) {
    pass++;
    console.log('  ok   ' + name);
  } else {
    fail++;
    failures.push(name + (detail ? ' :: ' + detail : ''));
    console.log('  FAIL ' + name + (detail ? '  ->  ' + detail : ''));
  }
}

function decodeB64Url(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  return decodeURIComponent(
    Array.from(b)
      .map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
      .join(''),
  );
}

/* ------------------------------------------------------------------ *
 * Case 1: shadowsocks 2022 format
 * ------------------------------------------------------------------ */
console.log('shadowsocks 2022 (synthetic sample)');
{
  const item = {
    name: 'SS-2022 Sample Node',
    address: '198.51.100.223:8080',
    v2rayProfile: {
      configType: '3',
      addedTime: '1790632298525',
      server: '198.51.100.223',
      serverPort: '8080',
      password: 'gXqk6/19VX5/wJYYbnV20Q==:6cVD2k4nm6xF0YXKa48ciQ==',
      method: '2022-blake3-aes-128-gcm',
      tlsAllowInsecure: 'false',
    },
  };

  const link = buildProfileLink(item);
  check('produces a link', link !== null);
  check('kind is shadowsocks', link && link.kind === 'shadowsocks', link && link.kind);
  check('scheme is ss://', link && link.value.startsWith('ss://'));

  // SIP002 userinfo must decode back to method:password
  const m = /^ss:\/\/([^@]+)@([^:]+):(\d+)/.exec(link.value);
  check('has host:port', m !== null);
  if (m) {
    const userInfo = decodeB64Url(m[1]);
    check(
      'userinfo decodes to method:password',
      userInfo === '2022-blake3-aes-128-gcm:gXqk6/19VX5/wJYYbnV20Q==:6cVD2k4nm6xF0YXKa48ciQ==',
      userInfo,
    );
    check('host preserved', m[2] === '198.51.100.223', m[2]);
    check('port preserved', m[3] === '8080', m[3]);
  }
  check('no vmess scheme leaked', link && !link.value.startsWith('vmess://'));
  check('readConfigType sees shadowsocks', readConfigType(item.v2rayProfile) === 'shadowsocks');
}

/* ------------------------------------------------------------------ *
 * Case 2: plain shadowsocks with a classic cipher
 * ------------------------------------------------------------------ */
console.log('shadowsocks classic cipher');
{
  const item = {
    name: 'ss-classic-sample',
    v2rayProfile: {
      configType: '3',
      method: 'chacha20-ietf-poly1305',
      server: '192.0.2.10',
      serverPort: '8388',
      password: 'secretpass',
    },
  };
  const link = buildProfileLink(item);
  check('produces ss://', link && link.value.startsWith('ss://'));
  const m = /^ss:\/\/([^@]+)@/.exec(link.value);
  check(
    'combines method and password',
    m && decodeB64Url(m[1]) === 'chacha20-ietf-poly1305:secretpass',
    m && decodeB64Url(m[1]),
  );
}

/* ------------------------------------------------------------------ *
 * Case 3: REALITY protocol handling
 * ------------------------------------------------------------------ */
console.log('REALITY protocol handling');
{
  const item = {
    name: 'reality-sample',
    v2rayProfile: {
      configType: '5',
      server: '192.0.2.20',
      serverPort: '443',
      password: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      method: 'none',
      security: 'reality',
      sni: 'gateway.example.org',
      network: 'tcp',
      headerType: 'none',
      insecure: 'false',
      flow: 'xtls-rprx-vision',
    },
  };
  const link = buildProfileLink(item);
  check('produces vless', link && link.kind === 'vless', link && link.kind);
  check('scheme is vless://', link && link.value.startsWith('vless://'));
  if (link) {
    const q = link.value.split('?')[1] || '';
    check('security=reality kept', q.includes('security=reality'), q.slice(0, 120));
    check('flow=xtls-rprx-vision kept', q.includes('flow=xtls-rprx-vision'));
    check('sni kept', q.includes('sni=gateway.example.org'));
    // the old code emitted security=none, which silently drops REALITY
    check('not downgraded to none', !q.includes('security=none'));
  }
  check('hasTls true for reality', hasTls(item.v2rayProfile) === true);
  check('isReality true', isReality(item.v2rayProfile) === true);
}

/* ------------------------------------------------------------------ *
 * Case 4: a vmess profile that is genuinely a vmess
 * ------------------------------------------------------------------ */
console.log('genuine vmess (fixture)');
{
  const item = {
    name: 'EU-Cloudflare-1',
    v2rayProfile: {
      configType: '1',
      server: 'example.com',
      serverPort: '443',
      password: 'b831381d-6324-4d53-ad4f-8cda48b30811',
      security: 'tls',
      network: 'ws',
      host: 'example.com',
      path: '/ws',
      sni: 'example.com',
    },
  };
  const link = buildProfileLink(item);
  check('produces vmess', link && link.kind === 'vmess', link && link.kind);
  if (link) {
    const payload = JSON.parse(decodeB64Url(link.value.slice('vmess://'.length)));
    check('id is the uuid', payload.id === 'b831381d-6324-4d53-ad4f-8cda48b30811');
    check('tls field is tls', payload.tls === 'tls', payload.tls);
    check('net is ws', payload.net === 'ws', payload.net);
    check('scy is auto not the cipher', payload.scy === 'auto', payload.scy);
  }
}

/* ------------------------------------------------------------------ *
 * Case 5: vless with tls (configType=5)
 * ------------------------------------------------------------------ */
console.log('vless with tls (configType=5)');
{
  const item = {
    name: 'vless-tls-sample',
    v2rayProfile: {
      configType: '5',
      server: '192.0.2.50',
      serverPort: '443',
      password: '11111111-2222-3333-4444-555555555555',
      security: 'tls',
      network: 'grpc',
      sni: 'example.org',
      insecure: 'false',
    },
  };
  const link = buildProfileLink(item);
  check('produces vless for configType=5', link && link.kind === 'vless', link && link.kind);
  check('scheme is vless://', link && link.value.startsWith('vless://'));
}

/* ------------------------------------------------------------------ *
 * Case 6: trojan, non-uuid with tls
 * ------------------------------------------------------------------ */
console.log('trojan (non-uuid + tls)');
{
  const item = {
    name: 'trojan-sample',
    v2rayProfile: {
      configType: '5',
      server: '192.0.2.90',
      serverPort: '443',
      password: 'not-a-uuid-value',
      security: 'tls',
      network: 'ws',
      host: 'cdn.example.org',
      path: '/',
      sni: 'cdn.example.org',
    },
  };
  const link = buildProfileLink(item);
  check('produces trojan', link && link.kind === 'trojan', link && link.kind);
  check('scheme is trojan://', link && link.value.startsWith('trojan://'));
}

/* ------------------------------------------------------------------ *
 * Case 7: guards. A bad profile must yield null, never a broken link.
 * ------------------------------------------------------------------ */
console.log('guards');
{
  check(
    'no server yields null',
    buildProfileLink({ name: 'x', v2rayProfile: { configType: '5' } }) === null,
  );
  check(
    'shadowsocks without password yields null',
    buildShadowsocksLink({ name: 'x', v2rayProfile: { configType: '3', server: 'a', serverPort: '1' } }) === null,
  );
  check(
    'unknown type with non-uuid and no tls yields null',
    buildProfileLink({
      name: 'x',
      v2rayProfile: { configType: '9', server: 'a', serverPort: '1', password: 'zzz' },
    }) === null,
  );
}

/* ------------------------------------------------------------------ *
 * Case 8: VLESS configuration with tcp, headerType=http, security=none
 * ------------------------------------------------------------------ */
console.log('VLESS HTTP Header Profile');
{
  const item = {
    name: 'VLESS HTTP Header Node',
    v2rayProfile: {
      configType: '5',
      password: 'c5837baa-8d0c-4272-ace0-3967ba90b0b1',
      server: '198.51.100.15',
      serverPort: 443,
      security: 'none',
      network: 'tcp',
      headerType: 'http',
      host: 'cdn1.example.org,cdn2.example.org',
    },
  };
  const link = buildProfileLink(item);
  check('user sample produces vless', link && link.kind === 'vless', link && link.kind);
  check('user sample scheme is vless://', link && link.value.startsWith('vless://'));
  check('security is none', link && link.value.includes('security=none'));
  check('headerType is http', link && link.value.includes('headerType=http'));
  check('type is tcp', link && link.value.includes('type=tcp'));
  check('host is preserved', link && link.value.includes('cdn1.example.org'));
}

/* ------------------------------------------------------------------ *
 * Case 9: IPv6 bracket formatting (RFC 3986)
 * ------------------------------------------------------------------ */
console.log('IPv6 bracket formatting (RFC 3986)');
{
  check('formats IPv4 as host:port', formatHostPort('192.0.2.1', 8080) === '192.0.2.1:8080');
  check('formats domain as host:port', formatHostPort('example.com', 443) === 'example.com:443');
  check('brackets IPv6 address', formatHostPort('2001:db8::1', 443) === '[2001:db8::1]:443');
  check('does not double bracket already-bracketed IPv6', formatHostPort('[2001:db8::1]', 443) === '[2001:db8::1]:443');
  check('unbracketHost strips brackets', unbracketHost('[2001:db8::1]') === '2001:db8::1');
  check('unbracketHost leaves unbracketed host alone', unbracketHost('2001:db8::1') === '2001:db8::1');

  // Verify profile link with IPv6
  const itemIpv6 = {
    name: 'ipv6-vless',
    v2rayProfile: {
      configType: '5',
      server: '2001:db8::1',
      serverPort: 443,
      password: '11111111-2222-3333-4444-555555555555',
      security: 'tls',
      network: 'tcp',
    },
  };
  const link = buildProfileLink(itemIpv6);
  check('IPv6 profile link has bracketed host', link && link.value.includes('@[2001:db8::1]:443'));
}

/* ------------------------------------------------------------------ *
 * Case 10: v2ray outbound link builders
 * ------------------------------------------------------------------ */
console.log('v2ray outbound link builders');
{
  // 1. VLESS outbound with reality
  const vlessOb = {
    protocol: 'vless',
    settings: {
      vnext: [
        {
          address: '203.0.113.10',
          port: 443,
          users: [
            {
              id: 'a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d',
              flow: 'xtls-rprx-vision',
              encryption: 'none',
            },
          ],
        },
      ],
    },
    streamSettings: {
      network: 'tcp',
      security: 'reality',
      realitySettings: {
        serverName: 'gateway.example.com',
        publicKey: 'pubkey123',
        shortId: 'short123',
        fingerprint: 'chrome',
      },
    },
  };
  const vlessLink = buildLinkFromOutbound(vlessOb, 'outbound-reality');
  check('outbound vless produces link', vlessLink !== null && vlessLink.kind === 'vless');
  check('outbound vless contains security=reality', vlessLink && vlessLink.value.includes('security=reality'));
  check('outbound vless contains pbk=pubkey123', vlessLink && vlessLink.value.includes('pbk=pubkey123'));
  check('outbound vless contains flow=xtls-rprx-vision', vlessLink && vlessLink.value.includes('flow=xtls-rprx-vision'));

  // 2. VMess outbound with ws
  const vmessOb = {
    protocol: 'vmess',
    settings: {
      vnext: [
        {
          address: '2001:db8::8',
          port: 8443,
          users: [
            {
              id: '12345678-1234-1234-1234-123456789abc',
              alterId: 0,
              security: 'auto',
            },
          ],
        },
      ],
    },
    streamSettings: {
      network: 'ws',
      security: 'tls',
      tlsSettings: {
        serverName: 'cdn.example.org',
      },
      wsSettings: {
        path: '/websocket',
        headers: { Host: 'cdn.example.org' },
      },
    },
  };
  const vmessLink = buildLinkFromOutbound(vmessOb, 'outbound-vmess');
  check('outbound vmess produces link', vmessLink !== null && vmessLink.kind === 'vmess');
  if (vmessLink) {
    const json = JSON.parse(decodeB64Url(vmessLink.value.slice('vmess://'.length)));
    check('vmess add is unbracketed IPv6', json.add === '2001:db8::8');
    check('vmess port is 8443', json.port === '8443');
    check('vmess path is /websocket', json.path === '/websocket');
    check('vmess net is ws', json.net === 'ws');
  }

  // 3. Trojan outbound
  const trojanOb = {
    protocol: 'trojan',
    settings: {
      servers: [
        {
          address: '203.0.113.25',
          port: 443,
          password: 'secret-password-123',
        },
      ],
    },
    streamSettings: {
      network: 'ws',
      security: 'tls',
      tlsSettings: {
        serverName: 'trojan.example.com',
      },
      wsSettings: {
        path: '/trpath',
      },
    },
  };
  const trojanLink = buildLinkFromOutbound(trojanOb, 'outbound-trojan');
  check('outbound trojan produces link', trojanLink !== null && trojanLink.kind === 'trojan');
  check('trojan URI contains password', trojanLink && trojanLink.value.includes('secret-password-123@'));
  check('trojan URI contains path', trojanLink && trojanLink.value.includes('path=%2Ftrpath'));

  // 4. Shadowsocks outbound
  const ssOb = {
    protocol: 'shadowsocks',
    settings: {
      servers: [
        {
          address: '203.0.113.30',
          port: 8388,
          method: 'aes-128-gcm',
          password: 'mypassword',
        },
      ],
    },
  };
  const ssLink = buildLinkFromOutbound(ssOb, 'outbound-ss');
  check('outbound shadowsocks produces link', ssLink !== null && ssLink.kind === 'shadowsocks');
  check('shadowsocks URI starts with ss://', ssLink && ssLink.value.startsWith('ss://'));
}

/* ------------------------------------------------------------------ *
 * Case 11: createEntryFromItem
 * ------------------------------------------------------------------ */
console.log('createEntryFromItem');
{
  const itemWithV2rayJson = {
    name: 'Proxy Node 1',
    v2rayProfile: {
      remarks: 'Fallback Name',
      v2rayJson: JSON.stringify({
        outbounds: [
          {
            tag: 'proxy',
            protocol: 'vless',
            settings: {
              vnext: [
                {
                  address: '198.51.100.1',
                  port: 443,
                  users: [{ id: '99999999-8888-7777-6666-555555555555' }],
                },
              ],
            },
            streamSettings: {
              network: 'tcp',
              security: 'none',
            },
          },
        ],
      }),
    },
  };

  const entry = createEntryFromItem(itemWithV2rayJson, 'test.npvs');
  check('creates entry from v2rayJson', entry !== null);
  check('entry name is Proxy Node 1', entry && entry.name === 'Proxy Node 1');
  check('entry proto is vless', entry && entry.proto === 'vless');
  check('entry links length is 1', entry && entry.links.length === 1);
  check('entry sourceFile is test.npvs', entry && entry.sourceFile === 'test.npvs');
}

console.log('');
if (fail === 0) {
  console.log(`all green (${pass} checks)`);
} else {
  console.log(`${fail} FAILED / ${pass} passed`);
  for (const f of failures) console.log('  - ' + f);
}
process.exit(fail === 0 ? 0 : 1);
