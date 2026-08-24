import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import process from 'node:process';
import { chromium, firefox, webkit } from 'playwright-core';

const PACK_ROOT = '/opt/ambit/runtime-pack/web-browser';
const bundleRoot = path.resolve(process.argv[2] ?? '');
const evidenceRoot = path.resolve(process.argv[3] ?? '');
const resultPath = path.resolve(process.argv[4] ?? '');
if (!bundleRoot || !evidenceRoot || !resultPath) throw new Error('web render arguments are incomplete');
if (!fs.statSync(bundleRoot).isDirectory() || !fs.statSync(evidenceRoot).isDirectory()) {
  throw new Error('web render directories are invalid');
}

const contentTypes = new Map([
  ['.css', 'text/css; charset=utf-8'],
  ['.gif', 'image/gif'],
  ['.html', 'text/html; charset=utf-8'],
  ['.ico', 'image/x-icon'],
  ['.jpeg', 'image/jpeg'],
  ['.jpg', 'image/jpeg'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json'],
  ['.mjs', 'text/javascript; charset=utf-8'],
  ['.png', 'image/png'],
  ['.svg', 'image/svg+xml'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.webp', 'image/webp'],
  ['.woff', 'font/woff'],
  ['.woff2', 'font/woff2'],
]);

const server = http.createServer((request, response) => {
  let requestPath;
  try {
    requestPath = decodeURIComponent((request.url ?? '/').split('?', 1)[0]);
  } catch {
    response.writeHead(400).end();
    return;
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { allow: 'GET, HEAD' }).end();
    return;
  }
  if (requestPath === '/') requestPath = '/index.html';
  const target = path.resolve(bundleRoot, `.${requestPath}`);
  if (!target.startsWith(`${bundleRoot}${path.sep}`) || !fs.existsSync(target)) {
    response.writeHead(404).end();
    return;
  }
  const metadata = fs.lstatSync(target);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, {
    'cache-control': 'no-store',
    'content-length': metadata.size,
    'content-security-policy': "default-src 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    'content-type': contentTypes.get(path.extname(target).toLowerCase()) ?? 'application/octet-stream',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
  if (request.method === 'HEAD') response.end();
  else fs.createReadStream(target).pipe(response);
});

await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const address = server.address();
if (!address || typeof address === 'string') throw new Error('local web service did not bind');
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
const cases = [];
try {
  for (const [browserName, browserType, expectedVersion] of browserTypes) {
    const browser = await browserType.launch({
      headless: true,
      chromiumSandbox: browserName === 'chromium',
    });
    if (browser.version() !== expectedVersion) {
      throw new Error(`${browserName} version differs: ${browser.version()}`);
    }
    try {
      for (const viewport of viewports) {
        const caseRoot = path.join(evidenceRoot, browserName, viewport.name);
        fs.mkdirSync(caseRoot, { recursive: true, mode: 0o700 });
        const context = await browser.newContext({
          viewport: { width: viewport.width, height: viewport.height },
          colorScheme: viewport.colorScheme,
          reducedMotion: viewport.reducedMotion,
          locale: 'en-US',
          timezoneId: 'UTC',
        });
        await context.tracing.start({ screenshots: true, snapshots: true, sources: false });
        const blockedRequests = [];
        const requests = [];
        await context.route('**/*', async (route) => {
          const target = new URL(route.request().url());
          if (target.hostname !== '127.0.0.1') {
            blockedRequests.push(route.request().url());
            await route.abort('blockedbyclient');
          } else {
            await route.continue();
          }
        });
        const page = await context.newPage();
        const consoleErrors = [];
        page.on('console', (message) => {
          if (message.type() === 'error') consoleErrors.push(message.text());
        });
        page.on('pageerror', (error) => consoleErrors.push(error.message));
        page.on('request', (request) => requests.push(request.url()));
        await page.addInitScript({ content: axeSource });
        await page.goto(origin, { waitUntil: 'networkidle' });
        const screenshotPath = path.join(caseRoot, 'viewport.png');
        await page.screenshot({ path: screenshotPath, fullPage: false });
        const aria = await page.locator('body').ariaSnapshot();
        const ariaPath = path.join(caseRoot, 'aria.txt');
        fs.writeFileSync(ariaPath, `${aria}\n`, { mode: 0o400 });
        const axe = await page.evaluate(async () => globalThis.axe.run(document));
        const geometry = await page.evaluate(() => ({
          scrollWidth: document.documentElement.scrollWidth,
          clientWidth: document.documentElement.clientWidth,
          scrollHeight: document.documentElement.scrollHeight,
          clientHeight: document.documentElement.clientHeight,
        }));
        const tracePath = path.join(caseRoot, 'trace.zip');
        await context.tracing.stop({ path: tracePath });
        await context.close();
        if (axe.violations.length !== 0) {
          throw new Error(
            `${browserName}/${viewport.name} accessibility violations: ${axe.violations
              .map(({ id }) => id)
              .sort()
              .join(',')}`,
          );
        }
        if (consoleErrors.length !== 0) {
          throw new Error(`${browserName}/${viewport.name} console errors`);
        }
        if (blockedRequests.length !== 0) {
          throw new Error(`${browserName}/${viewport.name} external requests attempted`);
        }
        if (geometry.scrollWidth > geometry.clientWidth) {
          throw new Error(`${browserName}/${viewport.name} horizontal overflow`);
        }
        cases.push({
          browser: browserName,
          browserVersion: browser.version(),
          viewport,
          screenshotPath,
          ariaPath,
          tracePath,
          screenshotBytes: fs.statSync(screenshotPath).size,
          requestPaths: [...new Set(requests.map((value) => new URL(value).pathname))].sort(),
          consoleErrorCount: 0,
          blockedExternalRequestCount: 0,
          accessibilityViolationCount: 0,
          horizontalOverflowPixels: 0,
          geometry,
        });
      }
    } finally {
      await browser.close();
    }
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
}
fs.writeFileSync(resultPath, `${JSON.stringify({ cases }, null, 2)}\n`, { mode: 0o400, flag: 'wx' });
