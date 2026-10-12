// Reports what Chrome thinks about this page's PWA installability.
//
//   node tools/check-pwa.mjs <url> [sessionCookie]
//
// Uses Chrome's own Page.getAppManifest and Page.getInstallabilityErrors, so
// the answer is exactly the one behind the browser's install prompt rather
// than a guess from reading the manifest.

const [, , url = 'http://127.0.0.1:8293/', cookie = ''] = process.argv;
const CDP = 'http://127.0.0.1:9222';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const targets = await (await fetch(`${CDP}/json`)).json();
const page = targets.find((t) => t.type === 'page');
if (!page) throw new Error('no page target; start Chrome with --remote-debugging-port=9222');

const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let nextId = 1;
const pending = new Map();
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    const { resolve, reject } = pending.get(m.id);
    pending.delete(m.id);
    if (m.error) reject(new Error(JSON.stringify(m.error)));
    else resolve(m.result);
  }
};
const send = (method, params = {}) => {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
};

// A phone-sized viewport, and pretend the platform is Android so Chrome
// evaluates the same criteria a phone would.
await send('Emulation.setDeviceMetricsOverride', {
  width: 412, height: 915, deviceScaleFactor: 2.625, mobile: true,
});
await send('Emulation.setUserAgentOverride', {
  userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
  platform: 'Android',
});

await send('Network.enable');
await send('Network.clearBrowserCookies');
if (cookie) {
  await send('Network.setCookie', {
    name: 'fb_session', value: cookie, domain: '127.0.0.1', path: '/', httpOnly: true,
  });
}

await send('Page.navigate', { url });
await sleep(3000); // let the app boot and the service worker register

console.log('page:', url);
console.log('secure context:', await send('Runtime.evaluate', {
  expression: 'String(window.isSecureContext)', returnByValue: true,
}).then((r) => r.result.value));

// --- manifest ---------------------------------------------------------------
const manifest = await send('Page.getAppManifest');
const errors = manifest.errors || [];
console.log('\nmanifest URL:', manifest.url || '(none)');
console.log('manifest parsed:', manifest.parsed ? 'yes' : 'NO');
if (errors.length) {
  console.log('manifest errors:');
  for (const e of errors) console.log('  -', e.critical ? '[critical]' : '[warning]', e.message);
}

const p = manifest.parsed || {};
console.log('  name        :', p.name);
console.log('  short_name  :', p.short_name);
console.log('  start_url   :', p.start_url);
console.log('  display     :', p.display);
console.log('  icons       :', (p.icons || []).map((i) => `${i.sizes}(${i.purpose || 'any'})`).join(', ') || 'NONE');

// --- service worker ---------------------------------------------------------
const sw = await send('ServiceWorker.enable').catch(() => null);
await sleep(500);
const reg = await send('Runtime.evaluate', {
  expression: `(async () => {
    const r = await navigator.serviceWorker.getRegistration();
    if (!r) return 'none';
    return JSON.stringify({
      scope: r.scope,
      scriptURL: (r.active || r.installing || r.waiting)?.scriptURL,
      state: (r.active || r.installing || r.waiting)?.state,
    });
  })()`,
  awaitPromise: true, returnByValue: true,
}).then((r) => r.result.value).catch((e) => 'error: ' + e.message);
console.log('\nservice worker:', sw ? reg : 'ServiceWorker.enable unavailable - ' + reg);

// --- chrome's own verdict ---------------------------------------------------
const inst = await send('Page.getInstallabilityErrors').catch((e) => ({ errors: [{ errorId: e.message }] }));
console.log('\nChrome installability:');
if (inst.errors && inst.errors.length) {
  for (const e of inst.errors) console.log('  -', e.errorId);
} else {
  console.log('  installable: YES (no blocking errors)');
}

ws.close();
process.exit(0);
