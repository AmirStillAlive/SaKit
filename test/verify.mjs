// راستی‌آزمایی: خروجی پورت جاوااسکریپت باید بایت‌به‌بایت با پایتون یکی باشد.
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTables, decryptFileText, pretty } from '../src/lib/npv.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..', '..');
const srcDir = process.argv[2];
if (!srcDir) {
  console.error('usage: node verify.mjs <dir-with-npvt>');
  process.exit(2);
}

setTables(JSON.parse(readFileSync(path.join(repo, 'npv_tables.json'), 'utf8')));

const files = readdirSync(srcDir).filter((f) => f.toLowerCase().endsWith('.npvt'));
let ok = 0, fail = 0;
for (const f of files) {
  const text = readFileSync(path.join(srcDir, f), 'utf8');
  const blobs = decryptFileText(text);
  const joined = blobs.map((b) => pretty(b)).join('\n');
  const h = createHash('sha256').update(joined, 'utf8').digest('hex');
  if (blobs.length) { ok++; } else { fail++; }
  console.log(`${h}  ${f}  (${blobs.length} blob)`);
}
console.log(`SUMMARY ${ok} ok / ${fail} fail`);
