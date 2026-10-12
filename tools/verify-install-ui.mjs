// Confirms the in-app "Install app" item appears once Chrome says the app is
// installable, and that it is hidden before that.
//
//   node tools/verify-install-ui.mjs <url> <sessionCookie>
//
// Chrome fires beforeinstallprompt only after it has evaluated the install
// criteria, so a hidden item beforehand and a visible one afterwards is the
// behaviour we want.

const [, , url, cookie] = process.argv;
const CDP = 'http://127.0.0.1:9222';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const targets = await (await fetch(`${CDP}/json`)).json();
const page = targets.find((t) => t.type === 'page');
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

const evaluate = async (expr) => {
  const { result, exceptionDetails } = await send('Runtime.evaluate', {
    expression: expr, awaitPromise: true, returnByValue: true,
  });
  if (exceptionDetails) throw new Error(exceptionDetails.text + ' ' + JSON.stringify(exceptionDetails.exception?.description || ''));
  return result.value;
};

await send('Emulation.setDeviceMetricsOverride', {
  width: 412, height: 915, deviceScaleFactor: 2.625, mobile: true,
});
await send('Emulation.setUserAgentOverride', {
  userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
  platform: 'Android',
});
await send('Network.enable');
await send('Network.clearBrowserCookies');
await send('Network.setCookie', {
  name: 'fb_session', value: cookie, domain: '127.0.0.1', path: '/', httpOnly: true,
});

await send('Page.navigate', { url });
await sleep(3500);

const before = await evaluate(`(() => {
  const b = document.getElementById('mi-install');
  return b ? b.hidden : 'missing';
})()`);
console.log('install item before Chrome decides:', before === true ? 'hidden (correct)' : before);

const events = await evaluate(`(async () => {
  const seen = [];
  window.addEventListener('beforeinstallprompt', () => seen.push('beforeinstallprompt'));
  await new Promise(r => setTimeout(r, 1500));
  const b = document.getElementById('mi-install');
  return JSON.stringify({
    sawEvent: seen.length > 0,
    hidden: b ? b.hidden : 'missing',
  });
})()`);
const parsed = JSON.parse(events);
console.log('Chrome fired beforeinstallprompt:', parsed.sawEvent);
console.log('install item after:', parsed.hidden === false ? 'VISIBLE (correct)' : 'hidden');

const errs = await send('Page.getInstallabilityErrors').catch(() => ({ errors: [] }));
console.log('Chrome installability errors:', errs.errors?.length ? errs.errors.map((e) => e.errorId).join(', ') : 'none');

ws.close();
process.exit(0);
