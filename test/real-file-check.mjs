/**
 * Feed a decrypted config JSON dump into the link builder.
 *
 * The real .npvs files are the user's own and must never enter the repo, so
 * this script works on a JSON dump instead. Decrypt first with:
 *   python tools/dump_configs.py <file.npvs> <password> out.json
 * then run:
 *   node web/test/real-file-check.mjs out.json
 */

import { readFileSync } from 'node:fs';
import { buildProfileLink, readConfigType, hasTls, isReality } from '../src/lib/links.ts';

const dump = process.argv[2];
if (!dump) {
  console.error('usage: node web/test/real-file-check.mjs <configs.json>');
  process.exit(2);
}

const parsed = JSON.parse(readFileSync(dump, 'utf8'));
const list = Array.isArray(parsed) ? parsed : [parsed];

let ok = 0;
let skipped = 0;
for (const c of list) {
  const p = c.v2rayProfile ?? {};
  const link = buildProfileLink(c);
  if (link) ok++;
  else skipped++;
  console.log(
    JSON.stringify(
      {
        name: c.name,
        configType: p.configType,
        detected: readConfigType(p),
        security: p.security ?? null,
        reality: isReality(p),
        hasTls: hasTls(p),
        kind: link ? link.kind : null,
        link: link ? link.value.slice(0, 120) : null,
      },
      null,
      2,
    ),
  );
}
console.log(`\nlinks built: ${ok}, skipped: ${skipped}, total: ${list.length}`);
