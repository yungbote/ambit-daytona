const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('/opt/ambit/runtime-pack/core-document/node/node_modules/playwright-core');
const AxeBuilder = require('/opt/ambit/runtime-pack/core-document/node/node_modules/@axe-core/playwright').default;

const outputRoot = path.resolve(process.argv[2]);
const url = process.argv[3];

(async () => {
  const browser = await chromium.launch({
    executablePath: '/usr/bin/chromium',
    headless: true,
    args: ['--disable-breakpad', '--disable-crash-reporter', '--disable-dev-shm-usage'],
  });
  const consoleErrors = [];
  const pageErrors = [];
  const externalRequests = [];
  const failedRequests = [];
  const screenshots = [];
  for (const viewport of [
    { name: 'desktop', width: 1440, height: 900 },
    { name: 'mobile', width: 390, height: 844 },
  ]) {
    const context = await browser.newContext({
      viewport: { width: viewport.width, height: viewport.height },
      locale: 'en-US',
      timezoneId: 'UTC',
      colorScheme: 'light',
    });
    await context.tracing.start({ screenshots: true, snapshots: true, sources: false });
    const page = await context.newPage();
    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text());
    });
    page.on('pageerror', (error) => pageErrors.push(error.message));
    page.on('requestfailed', (request) => {
      failedRequests.push(`${request.method()} ${request.url()}: ${request.failure()?.errorText ?? 'unknown'}`);
    });
    page.on('request', (request) => {
      if (!request.url().startsWith('http://127.0.0.1:8123/')) externalRequests.push(request.url());
    });
    await page.goto(url, { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'Ambit runtime conformance' }).waitFor();
    const axe = await new AxeBuilder({ page }).analyze();
    if (axe.violations.length > 0) {
      throw new Error(`accessibility violations: ${JSON.stringify(axe.violations)}`);
    }
    const screenshot = path.join(outputRoot, 'web', `runtime-${viewport.name}.png`);
    await page.screenshot({ path: screenshot, fullPage: true });
    const trace = path.join(outputRoot, 'web', `runtime-${viewport.name}-trace.zip`);
    await context.tracing.stop({ path: trace });
    screenshots.push({
      viewport: viewport.name,
      screenshot: path.relative(outputRoot, screenshot),
      trace: path.relative(outputRoot, trace),
    });
    await context.close();
  }
  await browser.close();
  if (consoleErrors.length > 0) throw new Error(`console errors: ${consoleErrors.join('; ')}`);
  if (pageErrors.length > 0) throw new Error(`page errors: ${pageErrors.join('; ')}`);
  if (failedRequests.length > 0) throw new Error(`failed requests: ${failedRequests.join('; ')}`);
  if (externalRequests.length > 0) throw new Error(`external requests: ${externalRequests.join('; ')}`);
  fs.writeFileSync(
    path.join(outputRoot, 'web-receipt.json'),
    `${JSON.stringify(
      {
        schema: 'ambit.runtime-pack-browser-conformance/v1',
        accessibilityViolations: 0,
        consoleErrors,
        pageErrors,
        failedRequests,
        externalRequests,
        screenshots,
      },
      null,
      2,
    )}\n`,
  );
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
