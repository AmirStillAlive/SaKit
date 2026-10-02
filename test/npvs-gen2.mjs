// تست نسخهٔ ۵ (gen2) در جاوااسکریپت + پاریتی با پایتون
//
// بردارها از تست Go پروژهٔ Pantegnos گرفته شده‌اند و fixture هم همان
// fixture عمومی MIT آن پروژه است.
//
//   node web/test/npvs-gen2.mjs

import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import {
  decryptNpvsGen2,
  gen2A16,
  gen2Kdk,
  gen2Configs,
  parseGen2Envelope,
  setGen2Tables,
} from '../src/lib/npvs_gen2.js';
import { gen2Sub7dc0 } from '../src/lib/npvs_gen2_sub7dc0.js';
import { NpvsError } from '../src/lib/npvs.js';

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
const tables = new Uint8Array(inflateSync(readFileSync(join(repoRoot, 'public', 'gen2_tables.bin.z'))));
setGen2Tables(tables);

// --- ۱. بردارهای A16 و KDK از تست Go -------------------------------------

console.log('بردارهای A16/KDK نسل ۲ (Pantegnos)');
const A16 = [
  ['b3e16e38809576cbf6aaafd638b6b070', 'ffd6b86349231c14b37f6c929e24cd42'],
  ['000102030405060708090a0b0c0d0e0f', 'f659c73d8c0fa5150e3254dfe0a1106d'],
  ['f7c7701d0117e9f1f0ce9508abb11519', '9821914745243955b1bdde3b7952303e'],
  ['c45a3c0407fcc90458a59f7b9d762617', 'e34dd0a6557a2a2dd41836e3d83740bc'],
  ['2eb61dd803807ce1f73f10aa8ae97711', '8eb1c4b1fa21daa7e4de7b8e4864f79a'],
  ['00000000000000000000000000000000', '4878126b14231f6f522f310686001524'],
  ['50d72fa987791d011e5d83e3e36ea971', '036ab758c7e097dc77b24b995908628a'],
];
for (const [salt, want] of A16) {
  check(`a16 ${salt.slice(0, 8)}..`, hex(gen2A16(Buffer.from(salt, 'hex'))), want);
}
const a16 = gen2A16(Buffer.from(A16[0][0], 'hex'));
check(
  'kdk',
  hex(await gen2Kdk(a16, Buffer.from('96b7d923079c7bc36d1310bd4d111a79', 'hex'))),
  '52043647a29853e765f8efe370fac47155616bfaf653d61b0075a2f183fb6b6b',
);

// --- ۲. بردارهای whitebox -------------------------------------------------

console.log('بردارهای whitebox نسل ۲');
const block0 = tables.subarray(0, 57344);
for (const [state, i, args, want] of [
  ['b395af7080aab038f6b66ecb38e176d6', 0, ['b51b86d6', 'e47f474c', 'e71972b9', '304961f0'], '8634d2d3'],
  ['f07431d5743484805ca10d3438e176d6', 3, ['e7099930', 'ee0a772e', '88de5cf1', '4b20a923'], 'cafd1bcc'],
]) {
  check(
    `sub7dc0 i=${i} ${state.slice(0, 8)}..`,
    hex(gen2Sub7dc0(block0, i, ...args.map((a) => parseInt(a, 16)))),
    want,
  );
}

// --- ۳. باز کردن fixture نسخهٔ ۵ ------------------------------------------

console.log('پاکت نسخهٔ ۵ (fixture عمومی Pantegnos)');
const fixturePath = join(repoRoot, 'test', 'fixtures', 'sample-gen2.npvs');
const fixture = new Uint8Array(readFileSync(fixturePath));
const env = parseGen2Envelope(fixture);
check('روش باز کردن appKey است', env.method, 2);

const res = await decryptNpvsGen2(fixture);
check('نسخه', res.meta.version, 5);
check('configId', res.meta.configId, '96b7d923079c7bc36d1310bd4d111a79');
check('تعداد کانفیگ', res.json.length, 1);
check('نام کانفیگ', res.json[0].name, 'Internet Server VPN / WhatsApp');
check('آدرس کانفیگ', res.json[0].address, 'help.snapchat.com:80');
check('یادداشت appKey', res.notes[0].startsWith('کلید با white-box نسل ۲'), true);
check(
  'KDK',
  res.keys.find(([k]) => k === 'KDK')[1],
  '52043647a29853e765f8efe370fac47155616bfaf653d61b0075a2f183fb6b6b',
);

// --- ۴. رمز عبور روی فایل بدون رمز ---------------------------------------

console.log('ورودی‌های خراب نسخهٔ ۵');
let threw = 0;
try {
  await decryptNpvsGen2(new Uint8Array([0x4e, 0x50, 0x56, 0x53, 5]));
} catch (e) {
  threw = e instanceof NpvsError ? 1 : 2;
}
check('فایل خیلی کوتاه رد شد', threw, 1);

// --- ۵. پاریتی با پایتون --------------------------------------------------

console.log('پاریتی پایتون و جاوااسکریپت (نسخهٔ ۵)');
{
  const dir = mkdtempSync(join(tmpdir(), 'npvs-gen2-'));
  try {
    const outDir = join(dir, 'out');
    execFileSync('python', [join(repoRoot, 'npvs.py'), fixturePath, outDir], {
      encoding: 'utf8',
      env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    });
    const pyText = readFileSync(join(outDir, 'sample-gen2.txt'), 'utf8');
    const jsHash = createHash('sha256').update(res.plaintext).digest('hex');
    const pyHash = createHash('sha256').update(pyText).digest('hex');
    check('هش خروجی دو زبان یکی است', jsHash, pyHash);
  } catch (e) {
    check('اجرای پایتون', String(e.message ?? e).slice(0, 120), 'ok');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log();
if (failed) {
  console.log(`${failed} آزمون شکست خورد`);
  process.exit(1);
}
console.log('همهٔ آزمون‌های نسخهٔ ۵ سبز است');
