// Reports layout metrics for the PWA at a given viewport, to catch overflow
// that a screenshot alone only hints at.
//
//   node tools/measure.mjs <url> [width] [height]

const [, , url = 'http://127.0.0.1:8199/', width = '390', height = '844'] = process.argv;
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

await send('Emulation.setDeviceMetricsOverride', {
  width: Number(width), height: Number(height), deviceScaleFactor: 1, mobile: true,
});
// Drop any session cookie from earlier runs so the login screen is measured
// rather than an already-authenticated file list.
await send('Network.enable');
await send('Network.clearBrowserCookies');
await send('Page.navigate', { url });
await sleep(2000);

const { result } = await send('Runtime.evaluate', {
  returnByValue: true,
  expression: `(() => {
    const r = (el) => el ? el.getBoundingClientRect() : null;
    const card = document.querySelector('#login .card, #bootstrap .card, #pwchange .card') || document.querySelector('.card');
    const centered = document.querySelector('#login:not([hidden]), #bootstrap:not([hidden]), #pwchange:not([hidden])');
    const cb = centered ? r(centered) : null;
    const kb = card ? r(card) : null;

    // Any element wider than the viewport causes horizontal scroll.
    const wide = [...document.querySelectorAll('body *')]
      .map((el) => ({ el, b: r(el) }))
      .filter(({ b }) => b && b.width > window.innerWidth + 0.5)
      .slice(0, 8)
      .map(({ el, b }) => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') +
        (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\\s+/).join('.') : '') +
        ' w=' + b.width.toFixed(1));

    return JSON.stringify({
      innerWidth: window.innerWidth,
      docScrollWidth: document.documentElement.scrollWidth,
      bodyScrollWidth: document.body.scrollWidth,
      horizontalOverflow: document.documentElement.scrollWidth > window.innerWidth,
      centered: cb && { x: +cb.x.toFixed(1), w: +cb.width.toFixed(1) },
      card: kb && { x: +kb.x.toFixed(1), w: +kb.width.toFixed(1), right: +kb.right.toFixed(1) },
      cardOverflowsViewport: kb ? kb.right > window.innerWidth + 0.5 || kb.x < -0.5 : null,
      widerThanViewport: wide,
    }, null, 2);
  })()`,
});

console.log(result.value);
ws.close();
process.exit(0);
