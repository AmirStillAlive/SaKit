// تولید بردار مرجع ChaCha20-Poly1305 با پیاده‌سازی مستقل Node
// تا تست پایتون و وب با یک مرجع بیرونی راستی‌آزمایی شود.
//
//   node web/test/chacha-vector.mjs

import { createCipheriv } from 'node:crypto';

const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const nonce = Buffer.from('000000000000004a00000000', 'hex');
const aad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
const plaintext = Buffer.from(
  "Ladies and Gentlemen of the class of '99: If I could offer you " +
    'only one tip for the future, sunscreen would be it.',
);

const cipher = createCipheriv('chacha20-poly1305', key, nonce);
cipher.setAAD(aad, { plaintextLength: plaintext.length });
const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();

console.log('CT  = ' + ct.toString('hex'));
console.log('TAG = ' + tag.toString('hex'));
