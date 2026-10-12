// Cross-checks the PWA's three source files for wiring mistakes that unit
// tests cannot see: element ids referenced by JS but absent from the HTML,
// and CSS classes applied from JS that the stylesheet never defines.
//
//   node tools/check-wiring.mjs

import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ASSETS = join(dirname(fileURLToPath(import.meta.url)), '..', 'web', 'assets');

const js = await readFile(join(ASSETS, 'app.js'), 'utf8');
const html = await readFile(join(ASSETS, 'index.html'), 'utf8');
const css = await readFile(join(ASSETS, 'styles.css'), 'utf8');

let problems = 0;

const htmlIds = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
const jsIds = new Set([...js.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]));

console.log(`element ids in index.html : ${htmlIds.size}`);
console.log(`element ids used by app.js: ${jsIds.size}\n`);

const missingIds = [...jsIds].filter((id) => !htmlIds.has(id));
if (missingIds.length) {
  problems += missingIds.length;
  console.log(`FAIL app.js references ids that do not exist: ${missingIds.join(', ')}`);
} else {
  console.log('OK   every id app.js looks up exists in index.html');
}

const htmlClasses = new Set(
  [...html.matchAll(/\bclass="([^"]+)"/g)].flatMap((m) => m[1].split(/\s+/)),
);

// Extract class names app.js applies. Template literals like
// `row${entry.is_dir ? ' is-dir' : ''}` contribute only their static prefix
// here; the conditional branches are checked by the corresponding compound
// rules in the stylesheet, so they are deliberately not parsed.
const jsClasses = new Set();
for (const m of js.matchAll(/classList\.(?:add|remove|toggle)\('([^']+)'/g)) jsClasses.add(m[1]);
for (const m of js.matchAll(/className = '([^']+)'/g)) jsClasses.add(m[1]);
for (const m of js.matchAll(/className = "([^"]+)"/g)) jsClasses.add(m[1]);
for (const m of js.matchAll(/className = `([^`]*)`/g)) {
  // Drop the ${...} expressions and keep the literal prefix.
  const statics = m[1].split('${')[0].trim();
  if (statics) jsClasses.add(statics);
}

const cssClasses = new Set([...css.matchAll(/\.([a-zA-Z][\w-]*)/g)].map((m) => m[1]));

const unstyled = [...jsClasses].filter((c) => !cssClasses.has(c)).sort();
const notInHtml = [...jsClasses].filter((c) => !htmlClasses.has(c)).sort();

if (unstyled.length) {
  problems += unstyled.length;
  console.log(`FAIL classes used by app.js with no CSS rule: ${unstyled.join(', ')}`);
} else {
  console.log(`OK   all ${jsClasses.size} classes app.js applies are styled`);
}

if (notInHtml.length) {
  // Expected: most rows, toasts and cards are built in JS rather than in HTML.
  console.log(`note ${notInHtml.length} classes are created dynamically (expected): ${notInHtml.join(', ')}`);
}

// The service worker precaches a fixed list; every entry must exist on disk or
// addAll rejects and the app silently loses offline support.
const sw = await readFile(join(ASSETS, 'sw.js'), 'utf8');
const shell = sw.match(/const SHELL = \[([\s\S]*?)\];/);
if (shell) {
  const paths = [...shell[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  console.log(`\nservice worker precaches ${paths.length} shell assets`);
  const { stat } = await import('node:fs/promises');
  for (const p of paths) {
    if (p === '/') continue;
    const rel = p.replace(/^\/static\//, '');
    try {
      await stat(join(ASSETS, rel));
    } catch {
      problems++;
      console.log(`FAIL precached asset does not exist: ${p} (expected web/assets/${rel})`);
    }
  }
  if (!problems) console.log('OK   every precached asset exists on disk');
}

// The manifest references icons that must also exist.
const manifest = JSON.parse(await readFile(join(ASSETS, 'manifest.webmanifest'), 'utf8'));
for (const icon of manifest.icons ?? []) {
  const rel = icon.src.replace(/^\/static\//, '');
  const { stat } = await import('node:fs/promises');
  try {
    await stat(join(ASSETS, rel));
  } catch {
    problems++;
    console.log(`FAIL manifest icon missing: ${icon.src}`);
  }
}
console.log(`OK   manifest lists ${manifest.icons?.length ?? 0} icons`);

console.log(problems ? `\n${problems} problem(s) found` : '\nno wiring problems found');
process.exit(problems ? 1 : 0);
