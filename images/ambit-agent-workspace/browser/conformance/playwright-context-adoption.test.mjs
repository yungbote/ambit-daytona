import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createServer as createPortServer } from 'node:net';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import test from 'node:test';

const modulePath = process.env.PLAYWRIGHT_CONTEXT_ADOPTION_MODULE;
const stockPath = process.env.PLAYWRIGHT_CONTEXT_STOCK_MODULE;
const chrome = process.env.PLAYWRIGHT_CONTEXT_CHROME;
assert(modulePath && stockPath && chrome, 'Set PLAYWRIGHT_CONTEXT_ADOPTION_MODULE, PLAYWRIGHT_CONTEXT_STOCK_MODULE, and PLAYWRIGHT_CONTEXT_CHROME to qualified local paths.');
const candidate = await import(pathToFileURL(resolve(modulePath)).href);
const stock = await import(pathToFileURL(resolve(stockPath)).href);

async function until(predicate, description) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail(description);
}

async function freePort() {
  const listener = createPortServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}

async function fixture(run) {
  const directory = await mkdtemp(join(tmpdir(), 'ambit-context-adoption-'));
  const requests = [];
  const server = createServer((request, response) => {
    requests.push({ url: request.url, host: request.headers.host });
    if (request.url === '/download') {
      response.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename=scope.txt' });
      response.end('retained download policy');
    } else {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><title>Context adoption</title><style>body{background:white;color:black}@media(prefers-color-scheme:dark){body{background:black;color:white}}</style><button>Observed page</button><a href="/download">Download</a>');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const port = await freePort();
  let owner;
  const attachments = [];
  try {
    owner = await stock.chromium.launchPersistentContext(join(directory, 'profile'), {
      executablePath: chrome, headless: true, viewport: null, acceptDownloads: true,
      downloadsPath: directory, args: [`--remote-debugging-port=${port}`],
    });
    const browser = owner.browser();
    assert.equal(browser.version(), '152.0.7977.82', 'qualification must use the pinned Chrome');
    const control = await browser.newBrowserCDPSession();
    const contexts = [owner];
    const pages = [];
    const ids = [];
    for (let index = 0; index < 3; index++) {
      if (index) contexts.push(await browser.newContext({ acceptDownloads: true, viewport: { width: 730 + index, height: 510 + index } }));
      const context = contexts[index];
      await context.addCookies([{ name: 'scope', value: `scope-${index}`, url: origin }]);
      const page = index ? await context.newPage() : context.pages()[0];
      await page.goto(origin);
      pages.push(page);
      const session = await context.newCDPSession(page);
      ids.push((await session.send('Target.getTargetInfo')).targetInfo.browserContextId);
      await session.detach();
    }
    const connect = async (module = candidate) => {
      const attached = await module.chromium.connectOverCDP(`http://127.0.0.1:${port}`, { noDefaults: true, isLocal: true, artifactsDir: directory });
      attachments.push(attached);
      return attached;
    };
    await run({ owner, browser, control, contexts, pages, ids, connect, directory, origin, requests });
  } finally {
    await Promise.all(attachments.map(browser => browser.close().catch(() => {})));
    await owner?.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}

async function contextId(context) {
  const page = context.pages()[0];
  assert(page, 'test context must have a page');
  const session = await context.newCDPSession(page);
  try { return (await session.send('Target.getTargetInfo')).targetInfo.browserContextId; }
  finally { await session.detach(); }
}

async function byScope(browser, origin) {
  const result = new Map();
  for (const context of browser.contexts()) {
    const scope = (await context.cookies(origin)).find(cookie => cookie.name === 'scope')?.value;
    if (scope) result.set(scope, context);
  }
  return result;
}

test('public marker distinguishes the source patch in ESM and CommonJS', () => {
  assert.equal(candidate.ambitCdpContextAdoptionVersion, 1);
  assert.equal(createRequire(import.meta.url)(resolve(modulePath).replace(/index\.mjs$/, 'index.js')).ambitCdpContextAdoptionVersion, 1);
  assert.equal(stock.ambitCdpContextAdoptionVersion, undefined);
});

test('stock 1.62.1 demonstrates the wrong-context baseline', { timeout: 30_000 }, async () => {
  await fixture(async ({ connect, origin, ids }) => {
    const baseline = await connect(stock);
    assert.equal(baseline.contexts().length, 1);
    const context = baseline.contexts()[0];
    const observed = new Set();
    for (const page of context.pages()) {
      const session = await context.newCDPSession(page);
      observed.add((await session.send('Target.getTargetInfo')).targetInfo.browserContextId);
      await session.detach();
    }
    assert.deepEqual(observed, new Set(ids));
    assert.equal((await context.cookies(origin)).find(cookie => cookie.name === 'scope').value, 'scope-0');
  });
});

test('default and two existing isolated contexts retain pages, cookies and newPage identity', { timeout: 30_000 }, async () => {
  await fixture(async ({ connect, origin, ids, contexts }) => {
    const attached = await connect();
    assert.equal(attached.contexts().length, 3);
    const adopted = await byScope(attached, origin);
    assert.equal(adopted.size, 3);
    for (let index = 0; index < 3; index++) {
      const context = adopted.get(`scope-${index}`);
      assert.equal(await contextId(context), ids[index]);
      assert.equal(context.pages().length, 1);
      assert.equal(context.pages()[0].context(), context);
      const page = await context.newPage();
      await page.goto(origin);
      const session = await context.newCDPSession(page);
      assert.equal((await session.send('Target.getTargetInfo')).targetInfo.browserContextId, ids[index]);
      await session.detach();
      assert.match(await page.evaluate(() => document.cookie), new RegExp(`scope=scope-${index}`));
      await context.addCookies([{ name: 'written', value: `only-${index}`, url: origin }]);
      assert.equal((await contexts[index].cookies(origin)).find(cookie => cookie.name === 'written').value, `only-${index}`);
      await context.clearCookies({ name: 'written' });
      assert(!(await contexts[index].cookies(origin)).some(cookie => cookie.name === 'written'));
    }
    await attached.close();
    const reattached = await connect();
    assert.equal(reattached.contexts().length, 3);
    assert.equal((await byScope(reattached, origin)).size, 3);
    for (const context of reattached.contexts()) assert.equal(context.pages().length, 2);
  });
});

test('later external targets publish one context and never merge into default', { timeout: 30_000 }, async () => {
  await fixture(async ({ connect, control, origin, ids }) => {
    const attached = await connect();
    let contextsPublished = 0;
    attached.on('context', () => contextsPublished++);
    const contextEvent = once(attached, 'context');
    const { browserContextId } = await control.send('Target.createBrowserContext');
    await control.send('Storage.setCookies', { browserContextId, cookies: [{ name: 'scope', value: 'external', url: origin }] });
    await Promise.all(Array.from({ length: 4 }, () => control.send('Target.createTarget', { browserContextId, url: origin })));
    const [context] = await contextEvent;
    await until(() => context.pages().length === 4, 'all external pages must become visible');
    assert.equal(contextsPublished, 1);
    assert.equal(attached.contexts().length, 4);
    assert.equal(await contextId(context), browserContextId);
    assert.equal((await context.cookies(origin)).find(cookie => cookie.name === 'scope').value, 'external');
    const defaultContext = (await byScope(attached, origin)).get('scope-0');
    assert.equal(await contextId(defaultContext), ids[0]);
    assert.equal(defaultContext.pages().length, 1);
    await context.newPage();
    await control.send('Target.disposeBrowserContext', { browserContextId });
    await until(() => !attached.contexts().includes(context), 'externally disposed context must close locally after target detach');
  });
});

test('owned context creation keeps requested options and explicit borrowed close is scoped', { timeout: 30_000 }, async () => {
  await fixture(async ({ connect, control, origin, ids }) => {
    const attached = await connect();
    const owned = await attached.newContext({ viewport: { width: 417, height: 293 }, locale: 'fr-FR' });
    const page = await owned.newPage();
    assert.deepEqual(await page.evaluate(() => ({ width: innerWidth, height: innerHeight, language: navigator.language })), { width: 417, height: 293, language: 'fr-FR' });
    const ownedId = await contextId(owned);
    const adopted = await byScope(attached, origin);
    await adopted.get('scope-1').close();
    let roster = await control.send('Target.getBrowserContexts');
    assert(!roster.browserContextIds.includes(ids[1]));
    assert(roster.browserContextIds.includes(ids[2]));
    assert(roster.browserContextIds.includes(ownedId));
    assert.equal((await adopted.get('scope-2').cookies(origin)).find(cookie => cookie.name === 'scope').value, 'scope-2');
    await attached.close();
    roster = await control.send('Target.getBrowserContexts');
    assert(roster.browserContextIds.includes(ids[2]), 'borrowed context survives detach');
    assert(!roster.browserContextIds.includes(ownedId), 'new owned context keeps upstream disposeOnDetach');
  });
});

test('empty borrowed contexts remain usable after their last page closes', { timeout: 30_000 }, async () => {
  await fixture(async ({ connect, control, origin }) => {
    const { browserContextId } = await control.send('Target.createBrowserContext');
    await control.send('Storage.setCookies', { browserContextId, cookies: [{ name: 'scope', value: 'empty', url: origin }] });
    const attached = await connect();
    const context = (await byScope(attached, origin)).get('empty');
    assert(context);
    assert.equal(context.pages().length, 0);
    const page = await context.newPage();
    assert.equal(await contextId(context), browserContextId);
    await page.close();
    assert(attached.contexts().includes(context), 'zero pages do not mean the context was disposed');
    const next = await context.newPage();
    await next.goto(origin);
    assert.match(await next.evaluate(() => document.cookie), /scope=empty/);
  });
});

test('targets closing during dynamic adoption leave the remaining context usable', { timeout: 30_000 }, async () => {
  await fixture(async ({ connect, control, origin }) => {
    const attached = await connect();
    for (let iteration = 0; iteration < 6; iteration++) {
      const { browserContextId } = await control.send('Target.createBrowserContext');
      const event = once(attached, 'context');
      const { targetId } = await control.send('Target.createTarget', { browserContextId, url: origin });
      await control.send('Target.closeTarget', { targetId });
      const [context] = await event;
      await until(() => context.pages().length === 0, 'closed target must not be resurrected');
      const page = await context.newPage();
      await page.goto(origin);
      assert.equal(await page.title(), 'Context adoption');
      assert.equal(await contextId(context), browserContextId);
      await context.close();
    }
    assert.equal(attached.contexts().length, 3);
  });
});

test('borrowed attachment preserves viewport, media, permissions, downloads and screenshots', { timeout: 30_000 }, async () => {
  await fixture(async ({ connect, contexts, pages, origin, directory }) => {
    await contexts[1].grantPermissions(['geolocation'], { origin });
    await contexts[1].setGeolocation({ latitude: 37.7, longitude: -122.4 });
    await pages[1].emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
    const observe = page => page.evaluate(async () => ({ width: innerWidth, height: innerHeight, dark: matchMedia('(prefers-color-scheme: dark)').matches, reduced: matchMedia('(prefers-reduced-motion: reduce)').matches, permission: (await navigator.permissions.query({ name: 'geolocation' })).state }));
    const before = await observe(pages[1]);
    const attached = await connect();
    const context = (await byScope(attached, origin)).get('scope-1');
    const page = context.pages()[0];
    assert.deepEqual(await observe(page), before);
    assert.equal(before.permission, 'granted');
    assert.equal(before.dark, true);
    assert.equal(before.reduced, true);
    assert((await page.screenshot()).length > 100);
    const downloadEvent = pages[1].waitForEvent('download');
    await page.getByRole('link', { name: 'Download' }).click();
    const download = await downloadEvent;
    assert.equal(await readFile(await download.path(), 'utf8'), 'retained download policy');
    assert((await download.path()).startsWith(directory));
    await page.emulateMedia({ colorScheme: 'light' });
    assert.equal(await page.evaluate(() => matchMedia('(prefers-color-scheme: dark)').matches), false);
    await context.clearPermissions();
    assert.equal(await page.evaluate(async () => (await navigator.permissions.query({ name: 'geolocation' })).state), 'prompt');
  });
});

test('an existing context proxy remains the browser network owner after adoption', { timeout: 30_000 }, async () => {
  await fixture(async ({ connect, control, requests, origin }) => {
    const { browserContextId } = await control.send('Target.createBrowserContext', { proxyServer: origin, proxyBypassList: '<-loopback>' });
    const { targetId } = await control.send('Target.createTarget', { browserContextId, url: 'about:blank' });
    const attached = await connect();
    const context = (await Promise.all(attached.contexts().map(async context => [await contextId(context), context]))).find(([id]) => id === browserContextId)[1];
    const page = context.pages()[0];
    const session = await context.newCDPSession(page);
    assert.equal((await session.send('Target.getTargetInfo')).targetInfo.targetId, targetId);
    await session.detach();
    await page.goto('http://proxy-routing-review.test/observed');
    assert.equal(await page.title(), 'Context adoption');
    assert(requests.some(request => request.url === 'http://proxy-routing-review.test/observed'));
    await attached.close();
    assert((await control.send('Target.getBrowserContexts')).browserContextIds.includes(browserContextId));
  });
});
