/**
 * Regression tests for the link builders.
 *
 * Every case here is taken from a real .npvs file that was decrypted on
 * 2026-09-29, or from the exact values the app already shipped. Before the
 * fix all of these produced a vmess link that no client accepts.
 *
 * Run: node web/test/links.test.mjs
 */

import {
  buildProfileLink,
  buildShadowsocksLink,
  readConfigType,
  hasTls,
  isReality,
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
 * Case 1: real shadowsocks 2022 file, "Finland (fast)"
 * source: Telegram Desktop, 1193 bytes, method=1, iters=600000
 * ------------------------------------------------------------------ */
console.log('shadowsocks 2022 (real file)');
{
  const item = {
    name: '\u{1F1EB}\u{1F1EE} Finland (fast)',
    address: '81.12.33.223:8080',
    v2rayProfile: {
      configType: '3',
      addedTime: '1790632298525',
      server: '81.12.33.223',
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
    check('host preserved', m[2] === '81.12.33.223', m[2]);
    check('port preserved', m[3] === '8080', m[3]);
  }
  check('no vmess scheme leaked', link && !link.value.startsWith('vmess://'));
  check('readConfigType sees shadowsocks', readConfigType(item.v2rayProfile) === 'shadowsocks');
}

/* ------------------------------------------------------------------ *
 * Case 2: plain shadowsocks with a classic cipher
 * source: real file 16895, "@nitruStore 4" and "@nitruStore 52"
 * ------------------------------------------------------------------ */
console.log('shadowsocks classic cipher (real file)');
{
  const item = {
    name: 'x',
    v2rayProfile: {
      configType: '3',
      method: 'chacha20-ietf-poly1305',
      server: '1.2.3.4',
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
 * Case 3: REALITY. This is the "lies about tls" bug.
 * source: real file 10937, 7 configs, all security=reality
 * ------------------------------------------------------------------ */
console.log('REALITY (real file 10937)');
{
  const item = {
    name: 'reality',
    v2rayProfile: {
      configType: '5',
      server: '1.2.3.4',
      serverPort: '443',
      password: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      method: 'none',
      security: 'reality',
      sni: 'www.filimo.com',
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
    check('sni kept', q.includes('sni=www.filimo.com'));
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
    name: 'g',
    v2rayProfile: {
      configType: '5',
      server: '5.6.7.8',
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
 * source: real file 16895, "@nitruStore 48" had a non-uuid with tls
 * ------------------------------------------------------------------ */
console.log('trojan (non-uuid + tls)');
{
  const item = {
    name: 't',
    v2rayProfile: {
      configType: '5',
      server: '9.9.9.9',
      serverPort: '443',
      password: 'not-a-uuid-value',
      security: 'tls',
      network: 'ws',
      host: 'cdn.example',
      path: '/',
      sni: 'cdn.example',
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
 * Case 8: user VLESS config with tcp, headerType=http, security=none
 * ------------------------------------------------------------------ */
console.log('user VLESS config (🚀🇺🇸 آمریکا)');
{
  const item = {
    name: '🚀🇺🇸 آمریکا.',
    v2rayProfile: {
      configType: '5',
      password: 'c5837baa-8d0c-4272-ace0-3967ba90b0b1',
      server: '206.206.103.213',
      serverPort: 443,
      security: 'none',
      network: 'tcp',
      headerType: 'http',
      host: 'cf-pages.coingecko.com,trafic.outbrain.com,wordpress.org',
    },
  };
  const link = buildProfileLink(item);
  check('user sample produces vless', link && link.kind === 'vless', link && link.kind);
  check('user sample scheme is vless://', link && link.value.startsWith('vless://'));
  check('security is none', link && link.value.includes('security=none'));
  check('headerType is http', link && link.value.includes('headerType=http'));
  check('type is tcp', link && link.value.includes('type=tcp'));
  check('host is preserved', link && link.value.includes('cf-pages.coingecko.com'));
}

console.log('');
if (fail === 0) {
  console.log(`all green (${pass} checks)`);
} else {
  console.log(`${fail} FAILED / ${pass} passed`);
  for (const f of failures) console.log('  - ' + f);
}
process.exit(fail === 0 ? 0 : 1);
