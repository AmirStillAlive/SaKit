// End-to-end browser test: launches built production bundle in headless browser,
// feeds an actual NPVS sample file, and validates rendered output.
// Tests the exact path a user takes, verifying bundle and UI integration.
//
//   node test/browser-e2e.mjs [docs folder] [--url=http://127.0.0.1:8137/]
//
// If --url is provided, connects directly without spawning a new server.
// Uses browser DevTools Protocol (CDP) with zero extra npm dependencies.

import { existsSync, mkdtempSync, rmSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');
const urlFlag = process.argv.slice(2).find((a) => a.startsWith('--url='));
const positional = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const docsDir = resolve(positional[0] ?? join(repoRoot, 'docs'));

const BROWSERS = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
];
const browser = BROWSERS.find((p) => existsSync(p));
if (!browser) {
  console.error('Chrome or Edge not found; browser test skipped.');
  process.exit(2);
}

let failed = 0;
const check = (name, got, want) => {
  if (got === want) {
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}\n       got:  ${got}\n       want: ${want}`);
  }
};
const checkHas = (name, haystack, needle) => {
  if (String(haystack).includes(needle)) {
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}\n       «${needle}» not in output`);
  }
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Lightweight CDP client over browser DevTools WebSocket. */
class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      const slot = this.pending.get(msg.id);
      if (slot) {
        this.pending.delete(msg.id);
        if (msg.error) slot.reject(new Error(msg.error.message));
        else slot.resolve(msg.result);
      }
    });
  }

  static async attach(port, timeoutMs = 25000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
        const page = list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
        if (page) {
          const ws = new WebSocket(page.webSocketDebuggerUrl);
          await new Promise((res, rej) => {
            ws.addEventListener('open', res, { once: true });
            ws.addEventListener('error', rej, { once: true });
          });
          return new Cdp(ws);
        }
      } catch {
        /* Server not ready yet */
      }
      if (Date.now() > deadline) throw new Error('Failed to connect to browser CDP port');
      await sleep(250);
    }
  }

  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  /** Evaluates JavaScript in page context and returns last expression value. */
  async eval(expression) {
    const r = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description ?? 'خطای اجرا');
    }
    return r.result.value;
  }
}

const port = 3200 + Math.floor(Math.random() * 500);
const cdpPort = port + 1;
const pageUrl = urlFlag ? urlFlag.slice('--url='.length) : `http://127.0.0.1:${port}/`;
const profile = mkdtempSync(join(tmpdir(), 'npvs-e2e-'));

const srv = urlFlag
  ? null
  : spawn('python', ['-m', 'http.server', String(port), '-d', docsDir], {
      stdio: 'ignore',
    });
const chrome = spawn(
  browser,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${profile}`,
    pageUrl,
  ],
  { stdio: 'ignore' },
);

const cleanup = async () => {
  chrome.kill();
  srv?.kill();
  // Browser profile directory remains temporarily locked after process termination
  for (let i = 0; i < 20; i++) {
    await sleep(250);
    try {
      rmSync(profile, { recursive: true, force: true });
      return;
    } catch {
      // Directory still locked, retry
    }
  }
};

const uploaded = join(docsDir, 'e2e-sample.npvs');
try {
  console.log('End-to-end browser test');
  copyFileSync(join(here, 'fixtures/sample-appkey.npvs'), uploaded);

  const cdp = await Cdp.attach(cdpPort);
  await cdp.send('Runtime.enable');

  // Wait for SaKit application shell to mount
  let initialReady = false;
  for (let i = 0; i < 80; i++) {
    initialReady = await cdp.eval(`!!document.querySelector('button') && document.body.innerText.includes('SaKit')`);
    if (initialReady) break;
    await sleep(250);
  }
  check('App mounted', initialReady, true);

  // Switch to NPV tool view
  await cdp.eval(`(() => {
    const btn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('NPV'));
    if (btn) btn.click();
  })()`);
  await sleep(600);

  // Wait for NPV tool component to render
  let ready = false;
  for (let i = 0; i < 80; i++) {
    ready = await cdp.eval(
      `!!document.querySelector('input[type=file]') && (document.querySelector('h1')?.textContent || '').includes('NPV')`,
    );
    if (ready) break;
    await sleep(250);
  }
  check('NPV tool loaded', ready, true);

  const title = await cdp.eval('document.title');
  checkHas('Title contains "SaKit"', title, 'SaKit');

  const heading = await cdp.eval('document.querySelector("h1")?.textContent ?? ""');
  check('Heading matches expected text', String(heading).trim(), 'رمزگشایی کانفیگ NPV Tunnel');

  // Feed NPVS file to file input and trigger decrypt action
  const result = await cdp.eval(`(async () => {
    const buf = new Uint8Array(await (await fetch('e2e-sample.npvs')).arrayBuffer());
    const file = new File([buf], 'sample.npvs');
    const input = document.querySelector('input[type=file]');
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));

    await new Promise(r => setTimeout(r, 500));
    const btn = [...document.querySelectorAll('button')]
      .find(b => b.textContent.includes('رمزگشایی کن'));
    if (!btn) return { error: 'button not found' };
    btn.click();

    for (let i = 0; i < 80; i++) {
      await new Promise(r => setTimeout(r, 250));
      const text = document.body.innerText;
      // Await decrypted configs count or error banner
      if (text.includes('استخراج شد') || text.includes('خطا')) {
        return { text: text.slice(0, 6000) };
      }
    }
    return { error: 'timeout', text: document.body.innerText.slice(0, 2000) };
  })()`);

  check('Completed without error', result?.error ?? '', '');
  const body = result?.text ?? '';

  console.log('  ---');
  console.log(
    String(body)
      .split('\n')
      .filter((l) => l.trim())
      .slice(0, 16)
      .map((l) => '  | ' + l.trim())
      .join('\n'),
  );
  console.log('  ---');

  // Validation: config name and generated link must appear on screen
  checkHas('Config name displayed', body, 'EU-Cloudflare-1');
  checkHas('Config server displayed', body, 'example.com:443');
  checkHas('vmess link generated', body, 'vmess://');
  checkHas('Config count displayed', body, '۱ کانفیگ استخراج شد');
  check('No error message displayed', String(body).includes('خطا'), false);

  // --- Version 5: on-demand compressed table download and decryption path ---
  console.log('  --- نسخهٔ ۵ ---');
  const uploaded5 = join(docsDir, 'e2e-sample-gen2.npvs');
  copyFileSync(join(here, 'fixtures/sample-gen2.npvs'), uploaded5);

  const result5 = await cdp.eval(`(async () => {
    const buf = new Uint8Array(await (await fetch('e2e-sample-gen2.npvs')).arrayBuffer());
    const file = new File([buf], 'sample-gen2.npvs');
    const input = document.querySelector('input[type=file]');
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));

    await new Promise(r => setTimeout(r, 500));
    const btn = [...document.querySelectorAll('button')]
      .find(b => b.textContent.includes('رمزگشایی کن'));
    if (!btn) return { error: 'button not found' };
    btn.click();

    for (let i = 0; i < 120; i++) {
      await new Promise(r => setTimeout(r, 250));
      const text = document.body.innerText;
      if (text.includes('استخراج شد') || text.includes('خطا')) {
        return { text: text.slice(0, 6000) };
      }
    }
    return { error: 'timeout', text: document.body.innerText.slice(0, 2000) };
  })()`);

  check('نسخهٔ ۵ بدون خطا باز شد', result5?.error ?? '', '');
  const body5 = String(result5?.text ?? '');
  console.log(
    body5
      .split('\n')
      .filter((l) => l.trim())
      .slice(0, 12)
      .map((l) => '  | ' + l.trim())
      .join('\n'),
  );
  checkHas('نام کانفیگ نسخهٔ ۵ نمایش داده شد', body5, 'Internet Server VPN / WhatsApp');
  checkHas('آدرس کانفیگ نسخهٔ ۵', body5, 'help.snapchat.com:80');
  checkHas('یادداشت white-box نسل ۲', body5, 'نسل ۲');

  rmSync(uploaded5, { force: true });
} catch (e) {
  failed++;
  console.log(`  FAIL اجرای آزمون: ${e.message}`);
} finally {
  await cleanup();
  rmSync(uploaded, { force: true });
}

if (failed) {
  console.log(`\n${failed} آزمون شکست خورد`);
  process.exit(1);
}
console.log('\nهمهٔ آزمون‌های مرورگر سبز است');

