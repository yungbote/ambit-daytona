import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import process from 'node:process';
import { chromium, firefox, webkit } from 'playwright-core';

const PACK_REF = 'ambit.runtime-pack/web-browser@1';
const PACK_ROOT = '/opt/ambit/runtime-pack/web-browser';
const OUTPUT_ROOT = path.resolve(process.argv[2] ?? '');
if (!process.argv[2] || !fs.statSync(OUTPUT_ROOT).isDirectory()) {
  throw new Error('an existing conformance output directory is required');
}

function canonicalJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256(file) {
  return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}

function filesUnder(root) {
  const result = [];
  function visit(directory) {
    for (const name of fs.readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error(`output symlink is forbidden: ${absolute}`);
      if (stat.isDirectory()) visit(absolute);
      else if (stat.isFile()) {
        result.push({
          path: path.relative(root, absolute).split(path.sep).join('/'),
          bytes: stat.size,
          sha256: sha256(absolute),
        });
      }
    }
  }
  visit(root);
  return result;
}

function parseGuard(file) {
  const values = {};
  for (const line of fs.readFileSync(file, 'utf8').trim().split('\n')) {
    const separator = line.indexOf('\t');
    if (separator <= 0) throw new Error('runtime guard receipt is malformed');
    const key = line.slice(0, separator);
    if (Object.hasOwn(values, key)) throw new Error('runtime guard receipt has duplicate keys');
    values[key] = line.slice(separator + 1);
  }
  const expected = {
    cap_eff: '0000000000000000',
    gid: '1000',
    network: 'none',
    no_new_privileges: '1',
    pack: 'web-browser',
    root_filesystem: 'read_only',
    runtime_installers: 'absent',
    seccomp_mode: '2',
    supplementary_groups: 'none',
    uid: '1000',
    user: 'daytona',
  };
  if (JSON.stringify(values) !== JSON.stringify(expected)) {
    throw new Error(`runtime guard mismatch: ${JSON.stringify(values)}`);
  }
  return values;
}

const appRoot = path.join(OUTPUT_ROOT, 'app');
const evidenceRoot = path.join(OUTPUT_ROOT, 'browser-evidence');
fs.mkdirSync(appRoot);
fs.mkdirSync(evidenceRoot);
fs.writeFileSync(
  path.join(appRoot, 'index.html'),
  `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Ambit browser conformance</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <a class="skip" href="#main">Skip to main content</a>
  <header><strong>Ambit QA fixture</strong><span>Offline</span></header>
  <main id="main">
    <section aria-labelledby="heading">
      <p class="eyebrow">Deterministic state</p>
      <h1 id="heading">Responsive browser verification</h1>
      <p>Validate layout, accessibility, console, network, interaction, and recovery feedback.</p>
      <form novalidate>
        <label for="email">Work email</label>
        <input id="email" name="email" type="email" required aria-describedby="email-help">
        <span id="email-help">Use a valid address to continue.</span>
        <button type="submit">Run check</button>
      </form>
      <p id="status" role="status" aria-live="polite">Waiting for input</p>
    </section>
    <aside aria-label="Verification summary">
      <h2>Captured</h2>
      <ul><li>Responsive state</li><li>Accessibility tree</li><li>Console and network</li></ul>
    </aside>
  </main>
  <script src="/app.js" defer></script>
</body>
</html>
`,
);
fs.writeFileSync(
  path.join(appRoot, 'style.css'),
  `:root{color-scheme:light dark;font-family:Arial,sans-serif;background:#f5f7fb;color:#172033}
*{box-sizing:border-box}body{margin:0;min-width:0}a.skip{position:absolute;left:-9999px}a.skip:focus{left:1rem;top:1rem;background:#fff;color:#111;padding:.75rem;z-index:2}
header{display:flex;justify-content:space-between;padding:1rem clamp(1rem,5vw,4rem);background:#14213d;color:#fff}
main{display:grid;grid-template-columns:minmax(0,2fr) minmax(16rem,1fr);gap:2rem;max-width:72rem;margin:0 auto;padding:clamp(1rem,5vw,4rem)}
section,aside{background:#fff;color:#172033;border:1px solid #cbd5e1;border-radius:1rem;padding:clamp(1rem,3vw,2rem);box-shadow:0 8px 30px #0f172a14}
.eyebrow{color:#174ea6;font-weight:700;text-transform:uppercase;letter-spacing:.08em}h1{font-size:clamp(2rem,5vw,4rem);line-height:1.05;margin:.5rem 0 1rem}
form{display:grid;gap:.75rem;margin-top:2rem}label{font-weight:700}input,button{font:inherit;border-radius:.6rem;padding:.8rem 1rem}input{border:2px solid #64748b;background:#fff;color:#111}input:user-invalid{border-color:#b42318}button{border:0;background:#174ea6;color:#fff;font-weight:700;cursor:pointer}button:focus-visible,input:focus-visible{outline:3px solid #f59e0b;outline-offset:3px}
#status{min-height:1.5rem;font-weight:700}li+li{margin-top:.5rem}@media(max-width:720px){main{grid-template-columns:1fr}aside{order:-1}}@media(prefers-reduced-motion:no-preference){button{transition:transform .15s ease}button:hover{transform:translateY(-1px)}}
@media(prefers-color-scheme:dark){:root{background:#0f172a;color:#f8fafc}section,aside{background:#172033;color:#f8fafc;border-color:#475569}.eyebrow{color:#93c5fd}input{background:#f8fafc;color:#111}}
`,
);
fs.writeFileSync(
  path.join(appRoot, 'app.js'),
  `const form=document.querySelector('form');const email=document.querySelector('#email');const status=document.querySelector('#status');form.addEventListener('submit',(event)=>{event.preventDefault();if(!email.validity.valid){email.setAttribute('aria-invalid','true');status.textContent='Enter a valid email address';email.focus();return;}email.removeAttribute('aria-invalid');status.textContent='Ready — browser check completed';});`,
);

const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
]);
const server = http.createServer((request, response) => {
  const requestPath = request.url === '/' ? '/index.html' : request.url;
  if (!requestPath || requestPath.includes('..') || request.method !== 'GET') {
    response.writeHead(404).end();
    return;
  }
  const target = path.join(appRoot, requestPath);
  if (!target.startsWith(`${appRoot}${path.sep}`) || !fs.existsSync(target)) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, {
    'content-type': contentTypes.get(path.extname(target)) ?? 'application/octet-stream',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  fs.createReadStream(target).pipe(response);
});
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const address = server.address();
if (!address || typeof address === 'string') throw new Error('local service did not bind a TCP port');
const origin = `http://127.0.0.1:${address.port}`;

const axeSource = fs.readFileSync(path.join(PACK_ROOT, 'node_modules/axe-core/axe.min.js'), 'utf8');
const browserTypes = [
  ['chromium', chromium, '151.0.7922.34'],
  ['firefox', firefox, '153.0'],
  ['webkit', webkit, '26.5'],
];
const viewports = [
  { name: 'mobile', width: 375, height: 812, colorScheme: 'light', reducedMotion: 'reduce' },
  { name: 'tablet', width: 768, height: 1024, colorScheme: 'dark', reducedMotion: 'no-preference' },
  { name: 'desktop', width: 1440, height: 900, colorScheme: 'light', reducedMotion: 'no-preference' },
];
const results = [];
try {
  for (const [browserName, browserType, expectedVersion] of browserTypes) {
    const browser = await browserType.launch({
      headless: true,
      // Playwright otherwise disables Chromium's sandbox by default. The
      // browser pack is a distinct high-risk parser boundary, so a passing
      // conformance run must prove that sandboxed Chromium actually launches.
      chromiumSandbox: browserName === 'chromium',
    });
    if (expectedVersion && browser.version() !== expectedVersion) {
      throw new Error(`${browserName} version mismatch: ${browser.version()}`);
    }
    for (const viewport of viewports) {
      const caseRoot = path.join(evidenceRoot, browserName, viewport.name);
      fs.mkdirSync(caseRoot, { recursive: true });
      const context = await browser.newContext({
        viewport: { width: viewport.width, height: viewport.height },
        colorScheme: viewport.colorScheme,
        reducedMotion: viewport.reducedMotion,
        locale: 'en-US',
        timezoneId: 'UTC',
        recordVideo: { dir: caseRoot, size: { width: viewport.width, height: viewport.height } },
      });
      await context.tracing.start({ screenshots: true, snapshots: true, sources: false });
      const page = await context.newPage();
      const video = page.video();
      const consoleErrors = [];
      const requests = [];
      page.on('console', (message) => {
        if (message.type() === 'error') consoleErrors.push(message.text());
      });
      page.on('pageerror', (error) => consoleErrors.push(error.message));
      page.on('request', (request) => requests.push(request.url()));
      await page.addInitScript({ content: axeSource });
      await page.goto(origin, { waitUntil: 'networkidle' });
      await page.screenshot({ path: path.join(caseRoot, 'initial.png'), fullPage: true });
      const aria = await page.locator('body').ariaSnapshot();
      fs.writeFileSync(path.join(caseRoot, 'aria.txt'), `${aria}\n`);
      const axe = await page.evaluate(async () => globalThis.axe.run(document));
      if (axe.violations.length !== 0) {
        throw new Error(`${browserName}/${viewport.name} axe violations: ${JSON.stringify(axe.violations)}`);
      }
      await page.locator('button').click();
      if (!(await page.locator('#email').evaluate((element) => element.matches(':invalid')))) {
        throw new Error('required-email validation did not activate');
      }
      await page.screenshot({ path: path.join(caseRoot, 'validation.png'), fullPage: true });
      await page.locator('#email').fill('qa@example.com');
      await page.locator('button').click();
      await page.getByRole('status').filter({ hasText: 'Ready' }).waitFor();
      await page.screenshot({ path: path.join(caseRoot, 'success.png'), fullPage: true });
      const geometry = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth,
        timing: performance.getEntriesByType('navigation')[0]?.toJSON() ?? null,
        resources: performance.getEntriesByType('resource').map((entry) => ({
          name: new URL(entry.name).pathname,
          duration: Math.round(entry.duration * 1000) / 1000,
          transferSize: entry.transferSize,
        })),
      }));
      if (geometry.scrollWidth > geometry.clientWidth) throw new Error('responsive layout overflowed horizontally');
      if (consoleErrors.length !== 0) throw new Error(`console errors: ${consoleErrors.join('; ')}`);
      if (requests.some((url) => new URL(url).hostname !== '127.0.0.1')) {
        throw new Error(`external network request observed: ${requests.join(', ')}`);
      }
      canonicalJson(path.join(caseRoot, 'observation.json'), {
        browser: browserName,
        browserVersion: browser.version(),
        viewport,
        consoleErrors,
        requests: [...new Set(requests)].sort(),
        axeViolationCount: 0,
        responsiveOverflowPixels: 0,
        geometry,
      });
      await context.tracing.stop({ path: path.join(caseRoot, 'trace.zip') });
      await context.close();
      if (video) {
        const videoPath = await video.path();
        fs.renameSync(videoPath, path.join(caseRoot, 'journey.webm'));
      }
      results.push({
        browser: browserName,
        browserVersion: browser.version(),
        viewport: viewport.name,
        outcome: 'passed',
      });
    }
    await browser.close();
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
}

const guard = parseGuard(path.join(OUTPUT_ROOT, 'runtime-guard.tsv'));
const pack = JSON.parse(fs.readFileSync(path.join(PACK_ROOT, 'pack.lock.json'), 'utf8'));
const files = filesUnder(OUTPUT_ROOT);
canonicalJson(path.join(OUTPUT_ROOT, 'conformance-receipt.json'), {
  schema: 'ambit.runtime-pack-conformance/v3',
  packRef: PACK_REF,
  outcome: 'passed',
  fullImage: true,
  network: 'none',
  runtime: guard,
  checks: pack.conformance.requiredChecks.map((ref) => ({ ref, outcome: 'passed' })),
  browserCases: results,
  browserSandbox: {
    chromium: 'required-and-launched',
    outerLinuxCapabilities: [],
    seccompMode: 2,
  },
  localService: {
    bind: '127.0.0.1:ephemeral',
    externalRequestCount: 0,
    signedPreviewAuthority: 'external-provider-required',
  },
  files,
});
