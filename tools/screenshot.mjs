// Screenshots the PWA over the Chrome DevTools Protocol.
//
//   node tools/screenshot.mjs <cookieValue> <outDir>
//
// Uses Node's built-in WebSocket, so there is no npm dependency. It signs in
// by planting the session cookie, then captures the file list, a subfolder and
// the admin panel at phone width.

const [, , cookie, outDir] = process.argv;
if (!cookie) {
  console.error('usage: node tools/screenshot.mjs <sessionCookie> <outDir>');
  process.exit(1);
}

const BASE = 'http://127.0.0.1:8199';
const CDP = 'http://127.0.0.1:9222';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- connect to the page target -------------------------------------------

const targets = await (await fetch(`${CDP}/json`)).json();
const page = targets.find((t) => t.type === 'page');
if (!page) throw new Error('no page target found; is Chrome running with --remote-debugging-port=9222?');

const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((res, rej) => {
  ws.onopen = res;
  ws.onerror = rej;
});

let nextId = 1;
const pending = new Map();
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(new Error(JSON.stringify(msg.error)));
    else resolve(msg.result);
  }
};

function send(method, params = {}) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}

// ---- capture console errors so silent JS failures surface ------------------

const consoleErrors = [];
await send('Runtime.enable');
await send('Log.enable');
ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data);
  if (m.method === 'Runtime.exceptionThrown') {
    consoleErrors.push(m.params.exceptionDetails?.exception?.description ?? 'exception');
  }
  if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') {
    consoleErrors.push(`${m.params.entry.source}: ${m.params.entry.text}`);
  }
});

// ---- iPhone-ish viewport ----------------------------------------------------

await send('Emulation.setDeviceMetricsOverride', {
  width: 390,
  height: 844,
  deviceScaleFactor: 2,
  mobile: true,
});

const { writeFile, mkdir } = await import('node:fs/promises');
const out = outDir || '.';
await mkdir(out, { recursive: true });

async function snap(name) {
  const { data } = await send('Page.captureScreenshot', { format: 'png' });
  await writeFile(`${out}/${name}.png`, Buffer.from(data, 'base64'));
  console.log('wrote', `${out}/${name}.png`);
}

// ---- the sign-in screen, before any cookie exists ---------------------------

await send('Network.enable');
await send('Network.clearBrowserCookies');
await send('Page.navigate', { url: BASE + '/' });
await sleep(2000);
await snap('01-login');

// ---- now sign in by planting the session cookie -----------------------------

await send('Network.setCookie', {
  name: 'fb_session',
  value: cookie,
  domain: '127.0.0.1',
  path: '/',
  httpOnly: true,
});

async function go(path, wait = 1600) {
  await send('Page.navigate', { url: BASE + path });
  await sleep(wait);
}

await go('/', 2000);
await snap('02-files');
await go('/photos');
await snap('03-subfolder');
await go('/photos/2024');
await snap('04-nested');

// Open the admin drawer so the user-management UI is captured too.
await send('Runtime.evaluate', {
  expression: `document.getElementById('btn-menu').click();
               setTimeout(() => { const u = document.getElementById('mi-users'); if (u) u.click(); }, 150);`,
});
await sleep(1800);
await snap('05-admin');

console.log(consoleErrors.length ? `\nCONSOLE ERRORS:\n${consoleErrors.join('\n')}` : '\nno console errors');
ws.close();
process.exit(0);
