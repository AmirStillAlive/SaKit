// تست NPVS در جاوااسکریپت
//
// بردارهای KDF از آزمون خود پروژهٔ Pantegnos گرفته شده‌اند، پس پیاده‌سازی
// جاوااسکریپت باید دقیقا همان کلیدهایی را بسازد که Go می‌سازد.
// علاوه بر آن یک پاکت واقعی NPVS ساخته می‌شود تا مسیر رمزگشایی از سر تا ته
// آزموده شود.
//
//   node web/test/npvs-parity.mjs

import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  setWbTables,
  custodianKdks,
  chachaOpen,
  chachaSeal,
  decryptNpvs,
  decodeSentinels,
  NpvsError,
  NeedsPassphrase,
} from '../src/lib/npvs.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

let failed = 0;
function check(name, got, want) {
  if (got === want) {
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}\n       got:  ${got}\n       want: ${want}`);
  }
}

const hex = (b) => Buffer.from(b).toString('hex');
const bytesFromHex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
// base64url بدون padding، همان چیزی که سرآیند واقعی NPVS استفاده می‌کند
const b64u = (b) => Buffer.from(b).toString('base64url').replace(/=+$/, '');

setWbTables(JSON.parse(readFileSync(join(repoRoot, 'npvs_tables.json'), 'utf8')));

// --- ۱. بردار KDF از آزمون Go ---------------------------------------------

console.log('custodian KDK (بردار آزمون Go)');
const kdks = await custodianKdks(bytesFromHex('843cc2c901ce91516c38cc6605b92e47'));
check('دو کلید ساخته شد', kdks.length, 2);
check('kdk[0]', hex(kdks[0]), 'a9c9058dca50d178b64e0318ad5362be8f8d4103dc83ce2bd0ccd7e404584e3d');
check('kdk[1]', hex(kdks[1]), '438a04b521a5952156441a76bee5d8377a67257ff7e8291b220023614d7933d5');

// --- ۲. ChaCha20-Poly1305 در برابر بردار مرجع ------------------------------

console.log('ChaCha20-Poly1305 (بردار مرجع)');
const KEY = Uint8Array.from({ length: 32 }, (_, i) => i);
const NONCE = bytesFromHex('000000000000004a00000000');
const AAD = bytesFromHex('50515253c0c1c2c3c4c5c6c7');
const PT = new TextEncoder().encode(
  "Ladies and Gentlemen of the class of '99: If I could offer you " +
    'only one tip for the future, sunscreen would be it.',
);

const sealed = chachaSeal(KEY, NONCE, PT, AAD);
check(
  'متن رمزشده',
  hex(sealed.subarray(0, PT.length)),
  '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0' +
    'bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d' +
    '807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab779373' +
    '65af90bbf74a35be6b40b8eedf2785e42874d',
);
check('تگ', hex(sealed.subarray(PT.length)), '3179267b0ba71e40a2ad866fce5f8052');
check(
  'رمزگشایی برمی‌گردد',
  new TextDecoder().decode(chachaOpen(KEY, NONCE, sealed, AAD)),
  new TextDecoder().decode(PT),
);

// --- ۳. نشانه‌ها ----------------------------------------------------------

console.log('نشانه‌های npvs1:');
const tok = Buffer.from('vless://uuid@host:443').toString('base64').replace(/=+$/, '');
check('رشته مبهم باز شد', decodeSentinels(`پیش npvs1:${tok} پس`), 'پیش vless://uuid@host:443 پس');
check('توکن خالی دست‌نخورده ماند', decodeSentinels('npvs1:!!!'), 'npvs1:!!!');
check('توکن نامعتبر دست‌نخورده ماند', decodeSentinels('npvs1:@@@@'), 'npvs1:@@@@');

// --- ۴. ساخت پاکت واقعی NPVS ---------------------------------------------

async function buildEnvelope({ dek, body, appKey, password = '' }) {
  const salt = bytesFromHex('000102030405060708090a0b0c0d0e0f');
  const wrapNonce = bytesFromHex('0c0d0e0f1011121314151617');

  let wrapKey;
  if (appKey) {
    wrapKey = (await custodianKdks(salt))[0];
  } else {
    const base = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'],
    );
    wrapKey = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations: 2000, hash: 'SHA-256' }, base, 256,
      ),
    );
  }

  const s = chachaSeal(wrapKey, wrapNonce, dek, salt);
  const blob = new Uint8Array(wrapNonce.length + s.length);
  blob.set(wrapNonce, 0);
  blob.set(s, wrapNonce.length);

  const wrap = appKey
    ? { kdf: 'wbaes-ctr-sha256', keyId: 1, salt: b64u(salt), wrap: b64u(blob) }
    : { iters: 2000, kdf: 'pbkdf2-hmac-sha256', salt: b64u(salt), wrap: b64u(blob) };

  const header = {
    v: 1,
    configId: 'cfg-test-1234',
    issuedAt: '2026-01-01T00:00:00Z',
    creator: { fp: 'c0ffee', pk: 'deadbeef' },
    policy: { displayMessage: 'کانفیگ تست', configVersion: 5 },
  };
  header[appKey ? 'appKey' : 'passphrase'] = wrap;

  const headerRaw = new TextEncoder().encode(JSON.stringify(header));
  const bodyNonce = bytesFromHex('6465666768696a6b6c6d6e6f');
  const bodyPart = chachaSeal(dek, bodyNonce, body, headerRaw);
  const sigPart = Uint8Array.from({ length: 64 }, (_, i) => (i * 7 + 11) % 256);

  const out = new Uint8Array(
    4 + 1 + 4 + headerRaw.length + 12 + 4 + bodyPart.length + sigPart.length,
  );
  const dv = new DataView(out.buffer);
  let o = 0;
  out.set([0x4e, 0x50, 0x56, 0x53], o); o += 4;
  out[o++] = 1;
  dv.setUint32(o, headerRaw.length, false); o += 4;
  out.set(headerRaw, o); o += headerRaw.length;
  out.set(bodyNonce, o); o += 12;
  dv.setUint32(o, bodyPart.length, false); o += 4;
  out.set(bodyPart, o); o += bodyPart.length;
  out.set(sigPart, o);
  return out;
}

console.log('پاکت NPVS با appKey (بدون رمز عبور)');
const appRes = await decryptNpvs(
  await buildEnvelope({
    dek: Uint8Array.from({ length: 32 }, (_, i) => i),
    body: new TextEncoder().encode(
      JSON.stringify({ name: 'EU-1', v2rayProfile: { server: 'example.com', serverPort: 443 } }),
    ),
    appKey: true,
  }),
);
check('متن درست باز شد', JSON.parse(appRes.plaintext).name, 'EU-1');
check('configId', appRes.meta.configId, 'cfg-test-1234');
check('پیام سازنده', appRes.meta.creatorMessage, 'کانفیگ تست');
check('JSON ساختاریافته', appRes.json.v2rayProfile.server, 'example.com');
check('یادداشت appKey', appRes.notes[0].startsWith('کلید از appKey'), true);

console.log('پاکت NPVS با رمز عبور');
const passEnv = await buildEnvelope({
  dek: Uint8Array.from({ length: 32 }, (_, i) => i + 32),
  body: new TextEncoder().encode('{"name":"with-password"}'),
  appKey: false,
  password: 'sirvdaram',
});
check(
  'متن درست باز شد',
  JSON.parse((await decryptNpvs(passEnv, 'sirvdaram')).plaintext).name,
  'with-password',
);

let threw = false;
try { await decryptNpvs(passEnv, 'eshtebah'); } catch (e) { threw = e instanceof NpvsError; }
check('رمز غلط رد شد', threw, true);

threw = false;
try { await decryptNpvs(passEnv); } catch (e) {
  threw = e instanceof NeedsPassphrase && e.creatorMessage === 'کانفیگ تست';
}
check('بدون رمز راهنمایی می‌دهد', threw, true);

// --- ۵. ورودی‌های خراب ---------------------------------------------------

console.log('ورودی‌های خراب');
for (const [name, bytes, frag] of [
  ['خیلی کوتاه', new Uint8Array([0x4e, 0x50, 0x56, 0x53, 1]), 'کوتاه'],
  ['امضای اشتباه', new Uint8Array(100), 'امضای NPVS'],
]) {
  let ok = false;
  try { await decryptNpvs(bytes); } catch (e) { ok = e.message.includes(frag); }
  check(name, ok, true);
}

// --- ۶. پاریتی بین پایتون و جاوااسکریپت -----------------------------------
//
// یک پاکت ساخته می‌شود، در فایلی موقت نوشته می‌شود، بعد هر دو پیاده‌سازی آن را
// باز می‌کنند و هش خروجی‌ها باید یکی باشد.

console.log('پاریتی پایتون و جاوااسکریپت');
{
  const { writeFileSync, mkdtempSync, rmSync } = await import('node:fs');
  const { execFileSync } = await import('node:child_process');
  const { tmpdir } = await import('node:os');
  const { createHash } = await import('node:crypto');

  const dir = mkdtempSync(join(tmpdir(), 'npvs-parity-'));
  const file = join(dir, 'sample.npvs');
  try {
    writeFileSync(file, Buffer.from(
      await buildEnvelope({
        dek: Uint8Array.from({ length: 32 }, (_, i) => i),
        body: new TextEncoder().encode(
          JSON.stringify({ name: 'Parity', v2rayProfile: { server: 'a.example', serverPort: 443 } }),
        ),
        appKey: true,
      }),
    ));

    const jsRes = await decryptNpvs(new Uint8Array(readFileSync(file)));
    const jsHash = createHash('sha256').update(jsRes.plaintext).digest('hex');

    // پایتون متن باز شده را در پوشهٔ دوم می‌نویسد
    const outDir = join(dir, 'out');
    execFileSync('python', [join(repoRoot, 'npvs.py'), file, outDir], {
      encoding: 'utf8',
      env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    });
    const pyText = readFileSync(join(outDir, 'sample.txt'), 'utf8');
    const pyHash = createHash('sha256').update(pyText).digest('hex');

    check('هش خروجی دو زبان یکی است', jsHash, pyHash);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log();
if (failed) {
  console.log(`${failed} آزمون شکست خورد`);
  process.exit(1);
}
console.log('همهٔ آزمون‌ها سبز است');
