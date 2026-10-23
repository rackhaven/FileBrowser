// PWA client for the file browser.
//
// Design notes:
//  * All rendering builds DOM nodes and sets textContent. Nothing derived from
//    a filename is ever passed to innerHTML, so a file called
//    `<img onerror=...>` is just text.
//  * No inline styles or scripts, so the strict CSP in the Go server applies
//    unmodified.
//  * Downloads hand off to the browser with a plain anchor. That is the only
//    approach that streams to the OS file manager instead of buffering a
//    multi-gigabyte file in memory, and it is what makes "Save to Files"
//    appear on iOS.

const API = {
  status: () => req('GET', '/api/status'),
  me: () => req('GET', '/api/auth/me'),
  login: (b) => req('POST', '/api/auth/login', b),
  logout: () => req('POST', '/api/auth/logout', {}),
  changePassword: (b) => req('POST', '/api/auth/password', b),
  bootstrap: (b) => req('POST', '/api/auth/bootstrap', b),
  list: (p) => req('GET', `/api/fs/list?path=${encodeURIComponent(p)}`),
  usage: (p) => req('GET', `/api/fs/usage?path=${encodeURIComponent(p)}&depth=10`),
  mkdir: (b) => req('POST', '/api/fs/mkdir', b),
  rename: (b) => req('POST', '/api/fs/rename', b),
  remove: (p) => req('POST', `/api/fs/delete?path=${encodeURIComponent(p)}`, {}),
  users: () => req('GET', '/api/admin/users'),
  createUser: (b) => req('POST', '/api/admin/users', b),
  updateUser: (id, b) => req('PATCH', `/api/admin/users/${encodeURIComponent(id)}`, b),
  deleteUser: (id) => req('DELETE', `/api/admin/users/${encodeURIComponent(id)}`, {}),
  resetPassword: (id, b) => req('POST', `/api/admin/users/${encodeURIComponent(id)}/password`, b),
};

/** Thrown for any non-2xx response, carrying a message fit to show a user. */
class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function req(method, url, body) {
  const opts = { method, credentials: 'same-origin', headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(url, opts);
  } catch {
    throw new ApiError(0, 'Cannot reach the server. Check your connection.');
  }

  if (res.status === 204) return null;

  const isJSON = (res.headers.get('Content-Type') || '').includes('application/json');
  const data = isJSON ? await res.json().catch(() => null) : null;

  if (!res.ok) {
    throw new ApiError(res.status, (data && data.error) || `Request failed (${res.status})`);
  }
  return data;
}

// ---------------------------------------------------------------- state ---

const state = {
  user: null,
  path: '/',
  entries: [],
  parent: '',
  canWrite: false,
  selected: null,
  filter: '',
};

// ------------------------------------------------------------------ dom ---

const $ = (id) => document.getElementById(id);

const el = {
  app: $('app'), login: $('login'), bootstrap: $('bootstrap'), pwchange: $('pwchange'),
  crumbs: $('crumbs'), list: $('list'), empty: $('empty'),
  count: $('status-count'), quota: $('status-quota'), fab: $('btn-fab'),
  scrim: $('scrim'), menu: $('menu'), admin: $('admin'), searchpane: $('searchpane'),
  sheet: $('sheet'), detail: $('detail'), toasts: $('toasts'),
};

// ----------------------------------------------------------- formatting ---

function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '';
  if (n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const now = Date.now();
  const diff = now - d.getTime();
  // Recent files are more useful described relatively.
  if (diff < 60e3) return 'just now';
  if (diff < 3600e3) return `${Math.floor(diff / 60e3)} min ago`;
  if (diff < 86400e3) return `${Math.floor(diff / 3600e3)} h ago`;
  if (diff < 7 * 86400e3) return `${Math.floor(diff / 86400e3)} d ago`;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function joinPath(dir, name) {
  return (dir === '/' ? '' : dir) + '/' + name;
}

function parentOf(p) {
  if (p === '/' || !p) return '/';
  const i = p.lastIndexOf('/');
  return i <= 0 ? '/' : p.slice(0, i);
}

// ---------------------------------------------------------------- icons ---

const ICON = {
  dir: '<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>',
  dirLocked: '<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><rect x="9" y="12" width="6" height="5" rx="1"/>',
  file: '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9.5" r="1.5"/><path d="M21 16l-5-5-5 5-3-3-5 5"/>',
  video: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M10 9l5 3-5 3z"/>',
  audio: '<path d="M9 18V5l10-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="16" cy="16" r="3"/>',
  archive: '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10a1 1 0 001 1h12a1 1 0 001-1V9"/><path d="M10 13h4"/>',
  code: '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4"/>',
  doc: '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>',
};

const IMAGE_EXT = /^.(png|jpe?g|gif|webp|avif|bmp|svg|heic|heif)$/i;
const VIDEO_EXT = /^.(mp4|mov|m4v|webm|avi|mkv)$/i;
const AUDIO_EXT = /^.(mp3|m4a|aac|wav|ogg|flac|opus)$/i;
const ARCHIVE_EXT = /^.(zip|tar|gz|tgz|bz2|xz|7z|rar|zst)$/i;
const CODE_EXT = /^.(js|mjs|ts|json|html|css|py|go|rs|sh|yaml|yml|toml|xml|sql)$/i;
const DOC_EXT = /^.(pdf|docx?|xlsx?|pptx?|md|txt|rtf|odt|epub)$/i;

/** Pick an icon key from a file name. */
function iconFor(entry) {
  if (entry.is_dir) return entry.partial ? 'dirLocked' : 'dir';
  const ext = entry.name.slice(entry.name.lastIndexOf('.'));
  if (IMAGE_EXT.test(ext)) return 'image';
  if (VIDEO_EXT.test(ext)) return 'video';
  if (AUDIO_EXT.test(ext)) return 'audio';
  if (ARCHIVE_EXT.test(ext)) return 'archive';
  if (CODE_EXT.test(ext)) return 'code';
  if (DOC_EXT.test(ext)) return 'doc';
  return 'file';
}

const INLINE_OK = /^.(png|jpe?g|gif|webp|avif|bmp|svg|pdf|mp4|webm)$/i;

function svgFor(key) {
  const wrap = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  wrap.setAttribute('viewBox', '0 0 24 24');
  wrap.setAttribute('aria-hidden', 'true');
  wrap.innerHTML = ICON[key] || ICON.file; // constant markup, never user input
  return wrap;
}

// --------------------------------------------------------------- toasts ---

function toast(message, kind = '') {
  const node = document.createElement('div');
  node.className = `toast${kind ? ' ' + kind : ''}`;
  node.textContent = message;
  el.toasts.append(node);
  setTimeout(() => node.remove(), kind === 'err' ? 5200 : 2800);
}

// --------------------------------------------------------------- panels ---

function openPanel(node) {
  el.menu.hidden = true;
  el.admin.hidden = true;
  el.searchpane.hidden = true;
  node.hidden = false;
  el.scrim.hidden = false;
}

function closePanels() {
  el.menu.hidden = true;
  el.admin.hidden = true;
  el.searchpane.hidden = true;
  el.scrim.hidden = true;
}

// ---------------------------------------------------------------- sheet ---

/**
 * Show a modal sheet and resolve with the trimmed input value, or null if the
 * user cancelled.
 */
function promptSheet({ title, text = '', label = 'Value', value = '', ok = 'OK', textarea = false }) {
  return new Promise((resolve) => {
    $('sheet-title').textContent = title;
    $('sheet-text').textContent = text;
    $('sheet-text').hidden = !text;
    $('sheet-label').textContent = label;
    $('sheet-ok').textContent = ok;
    $('sheet-error').hidden = true;
    $('sheet-field').hidden = !label;

    const input = $('sheet-input');
    const area = $('sheet-area');
    input.hidden = textarea;
    area.hidden = !textarea;
    if (textarea) { area.value = value; } else { input.value = value; }

    const target = textarea ? area : input;

    const onClose = () => {
      el.sheet.removeEventListener('close', onClose);
      // value "ok" means the primary button was used; Escape gives null.
      resolve(el.sheet.returnValue === 'ok' ? target.value.trim() : null);
    };
    el.sheet.addEventListener('close', onClose);

    el.sheet.showModal();
    setTimeout(() => target.focus(), 30);
  });
}

function confirmSheet(title, text, ok = 'OK') {
  return promptSheet({ title, text, label: '', ok }).then((v) => v !== null);
}

// ------------------------------------------------------------ rendering ---

function renderCrumbs(path) {
  el.crumbs.replaceChildren();

  const root = document.createElement('button');
  root.className = 'crumb';
  root.textContent = 'Home';
  root.addEventListener('click', () => navigate('/'));
  el.crumbs.append(root);

  if (path === '/') {
    root.setAttribute('aria-current', 'page');
    return;
  }

  const parts = path.split('/').filter(Boolean);
  let acc = '';
  parts.forEach((seg, i) => {
    acc += '/' + seg;
    const sep = document.createElement('span');
    sep.className = 'crumb-sep';
    sep.textContent = '/';
    const btn = document.createElement('button');
    btn.className = 'crumb';
    btn.textContent = seg;
    const target = acc;
    btn.addEventListener('click', () => navigate(target));
    if (i === parts.length - 1) btn.setAttribute('aria-current', 'page');
    el.crumbs.append(sep, btn);
  });
}

function makeRow(entry) {
  const row = document.createElement('div');
  row.className = `row${entry.is_dir ? ' is-dir' : ''}`;
  row.setAttribute('role', 'listitem');
  row.tabIndex = 0;
  row.dataset.path = entry.path;

  const icon = document.createElement('span');
  icon.className = 'row-icon';
  icon.append(svgFor(iconFor(entry)));

  const text = document.createElement('span');
  text.className = 'row-text';

  const name = document.createElement('span');
  name.className = 'row-name';
  name.textContent = entry.name;

  const sub = document.createElement('span');
  sub.className = 'row-sub';
  if (entry.is_dir) {
    sub.textContent = entry.partial ? 'Contains shared folders' : 'Folder';
  } else {
    const size = formatBytes(entry.size);
    const when = formatDate(entry.mod_time);
    sub.textContent = [size, when].filter(Boolean).join(' · ');
  }
  text.append(name, sub);

  row.append(icon, text);

  // Show the permission level so users understand why some actions are absent.
  if (entry.access && entry.access !== 'read') {
    const tag = document.createElement('span');
    tag.className = 'row-tag';
    tag.textContent = entry.access;
    row.append(tag);
  }

  const activate = () => onEntryTap(entry, row);
  row.addEventListener('click', activate);
  row.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); }
  });

  return row;
}

function renderList() {
  const items = state.filter
    ? state.entries.filter((e) => e.name.toLowerCase().includes(state.filter))
    : state.entries;

  const frag = document.createDocumentFragment();
  for (const entry of items) frag.append(makeRow(entry));
  el.list.replaceChildren(frag);

  const nothing = items.length === 0;
  el.empty.hidden = !nothing;
  el.empty.textContent = state.filter
    ? `Nothing matches “${state.filter}”.`
    : 'This folder is empty.';

  const dirs = items.filter((e) => e.is_dir).length;
  const files = items.length - dirs;
  el.count.textContent = state.filter
    ? `${items.length} shown`
    : `${dirs} folder${dirs === 1 ? '' : 's'}, ${files} file${files === 1 ? '' : 's'}`;

  state.selected = null;
}

async function refreshQuota() {
  try {
    const u = await API.usage(state.path);
    el.quota.textContent = `${formatBytes(u.bytes)} · ${u.files} files`;
  } catch {
    el.quota.textContent = '';
  }
}

/**
 * The folder currently shown, derived from the URL path.
 *
 * The app uses real paths (/photos/2024) rather than a hash so links are
 * shareable and survive a reload: the server returns the same shell for any
 * non-API path, so boot() can read this straight back.
 */
function currentPath() {
  try {
    const p = decodeURIComponent(location.pathname || '/');
    return p === '/' ? '/' : p.replace(/\/+$/, '') || '/';
  } catch {
    // A malformed percent-encoding should not blank the whole UI.
    return '/';
  }
}

async function navigate(path, { push = true } = {}) {
  try {
    const data = await API.list(path || '/');
    state.path = data.path;
    state.entries = data.entries || [];
    state.parent = data.parent || '';
    state.canWrite = !!data.can_write;
    state.filter = '';
    $('search-input').value = '';

    renderCrumbs(state.path);
    renderList();
    refreshQuota();

    $('mi-up').hidden = !state.parent;
    $('mi-mkdir').hidden = !state.canWrite;
    el.fab.hidden = !state.canWrite;

    if (push && location.pathname !== state.path) {
      history.pushState({ path: state.path }, '', state.path);
    }
  } catch (err) {
    if (err.status === 401) return showLogin();
    toast(err.message, 'err');
    // An inaccessible folder leaves the view where it was, which is less
    // confusing than blanking the list.
    if (state.entries.length === 0) {
      el.list.replaceChildren();
      el.empty.textContent = err.message;
      el.empty.hidden = false;
    }
  }
}

// ------------------------------------------------------------- download ---

/**
 * Hand a file to the browser to save.
 *
 * We use a real anchor rather than fetch+blob on purpose: fetch+blob has to
 * hold the entire file in memory, which fails on a 4 GB video and offers no
 * "Save to Files" sheet on iOS. Letting the browser stream it is both lighter
 * and gives the user their native picker.
 */
function startDownload(entry, { inline = false } = {}) {
  const url = `/api/fs/download?path=${encodeURIComponent(entry.path)}${inline ? '&inline=1' : ''}`;
  const a = document.createElement('a');
  a.href = url;
  a.download = inline ? '' : entry.name;
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();

  toast(inline ? `Opening ${entry.name}` : `Downloading ${entry.name}`);
}

// ----------------------------------------------------------------- zips ---

/**
 * Stream a whole folder as a zip archive.
 *
 * Same hand-off to the browser as single-file downloads: a real anchor lets
 * the browser stream it, which matters for folders holding gigabytes. The
 * server names the archive, which is why the anchor's download slot is left
 * empty rather than set here.
 */
function startZip() {
  const url = `/api/fs/zip?path=${encodeURIComponent(state.path)}`;
  const a = document.createElement('a');
  a.href = url;
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();
  toast('Preparing a zip of this folder');
}

// ----------------------------------------------------------------- taps ---

function onEntryTap(entry, row) {
  if (entry.is_dir) {
    navigate(entry.path);
    return;
  }

  // A single tap downloads, which is the thing a phone user wants most. Tapping
  // the same row again opens the detail sheet for the other actions, so rename
  // and delete stay reachable without a long-press or context menu.
  if (state.selected === entry.path) {
    openDetail(entry);
    return;
  }
  for (const prev of el.list.querySelectorAll('.sel')) prev.classList.remove('sel');
  row.classList.add('sel');
  state.selected = entry.path;
  startDownload(entry);
}

function openDetail(entry) {
  $('detail-name').textContent = entry.name;
  const bits = [];
  if (!entry.is_dir) bits.push(formatBytes(entry.size));
  bits.push(formatDate(entry.mod_time));
  if (entry.access) bits.push(`access: ${entry.access}`);
  $('detail-meta').textContent = bits.filter(Boolean).join(' · ');

  $('d-download').textContent = entry.is_dir ? 'Folder' : 'Download';
  // Write access on this folder is what authorises renaming and deleting.
  const canModify = state.canWrite;
  $('d-rename').hidden = !canModify;
  $('d-delete').hidden = !canModify;

  $('d-download').onclick = () => { el.detail.hidden = true; doDownload(entry); };
  $('d-rename').onclick = () => { el.detail.hidden = true; doRename(entry); };
  $('d-delete').onclick = () => { el.detail.hidden = true; doDelete(entry); };
  $('d-cancel').onclick = () => {
    el.detail.hidden = true;
    // Reset selection so the next tap downloads again instead of reopening.
    state.selected = null;
    for (const prev of el.list.querySelectorAll('.sel')) prev.classList.remove('sel');
  };

  el.detail.hidden = false;
}

async function doDownload(entry) {
  if (entry.is_dir) {
    toast('Folder download is not supported yet — open the folder and pick files.');
    return;
  }
  // Images and PDFs open inline when the browser can display them, which is
  // what a user double-tapping a photo on a phone expects.
  const ext = entry.name.slice(entry.name.lastIndexOf('.'));
  if (INLINE_OK.test(ext)) startDownload(entry, { inline: true });
  else startDownload(entry);
}

async function doRename(entry) {
  const name = await promptSheet({
    title: 'Rename',
    text: entry.path,
    label: 'New name',
    value: entry.name,
    ok: 'Rename',
  });
  if (!name || name === entry.name) return;
  if (name.includes('/')) return toast('A name cannot contain a slash.', 'err');

  try {
    await API.rename({ from: entry.path, to_dir: state.path, new_name: name });
    toast('Renamed');
    navigate(state.path, { push: false });
  } catch (err) {
    toast(err.message, 'err');
  }
}

async function doDelete(entry) {
  const ok = await confirmSheet(
    `Delete ${entry.name}?`,
    entry.is_dir ? 'The folder and everything inside it will be permanently removed.' : 'This cannot be undone.',
    'Delete'
  );
  if (!ok) return;

  try {
    await API.remove(entry.path);
    toast('Deleted');
    navigate(state.path, { push: false });
  } catch (err) {
    toast(err.message, 'err');
  }
}

// --------------------------------------------------------------- uploads ---

function pickFile(dir, accept) {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    if (accept) input.accept = accept;
    input.addEventListener('change', () => resolve(Array.from(input.files || [])), { once: true });
    // A cancelled picker fires no event in most browsers; the promise simply
    // never resolves, which is harmless because nothing awaits it later.
    input.click();
  });
}

/**
 * Upload one file with a progress toast.
 *
 * Uses XHR rather than fetch because we need upload progress, which the fetch
 * API still cannot report. The body is the File itself, so the browser streams
 * it without ever materialising it in JS memory.
 */
function uploadFile(file, dir) {
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    const url = `/api/fs/upload?path=${encodeURIComponent(dir)}&name=${encodeURIComponent(file.name)}`;

    const label = document.createElement('div');
    label.className = 'toast';
    const title = document.createElement('div');
    title.textContent = `Uploading ${file.name}`;
    const bar = document.createElement('progress');
    bar.max = 1;
    bar.value = 0;
    label.append(title, bar);
    el.toasts.append(label);

    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable) bar.value = e.loaded / e.total;
    });

    xhr.addEventListener('load', () => {
      label.remove();
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(true);
      } else {
        let msg = `Upload failed (${xhr.status})`;
        try { msg = JSON.parse(xhr.responseText).error || msg; } catch { /* keep default */ }
        toast(msg, 'err');
        resolve(false);
      }
    });

    xhr.addEventListener('error', () => {
      label.remove();
      toast('Upload failed: network error', 'err');
      resolve(false);
    });
    xhr.addEventListener('abort', () => {
      label.remove();
      resolve(false);
    });

    xhr.open('PUT', url, true);
    xhr.send(file);
  });
}

async function doUpload() {
  const files = await pickFile(state.path);
  if (!files.length) return;

  let ok = 0;
  for (const file of files) {
    // Sequential, so progress toasts do not pile up and mobile radios stay sane.
    if (await uploadFile(file, state.path)) ok++;
  }
  if (ok) {
    toast(`Uploaded ${ok} file${ok === 1 ? '' : 's'}`);
    navigate(state.path, { push: false });
  }
}

async function doMkdir() {
  const name = await promptSheet({
    title: 'New folder',
    label: 'Folder name',
    ok: 'Create',
  });
  if (!name) return;
  if (name.includes('/')) return toast('A name cannot contain a slash.', 'err');

  try {
    await API.mkdir({ path: state.path, name });
    toast('Folder created');
    navigate(state.path, { push: false });
  } catch (err) {
    toast(err.message, 'err');
  }
}

// ---------------------------------------------------------------- search ---

function onSearchInput() {
  state.filter = $('search-input').value.trim().toLowerCase();
  renderList();
}

// ---------------------------------------------------------- user admin ---

/** Render the editable grant list as simple text lines: "<path> <level>". */
function grantsToText(grants) {
  if (!grants || !grants.length) return '/ read';
  return grants.map((g) => `${g.path} ${g.level}`).join('\n');
}

function textToGrants(text) {
  const grants = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const idx = line.lastIndexOf(' ');
    if (idx <= 0) throw new Error(`Line “${line}” needs a path and a level.`);
    const path = line.slice(0, idx).trim();
    const level = line.slice(idx + 1).trim().toLowerCase();
    if (!['read', 'write', 'admin'].includes(level))
      throw new Error(`“${level}” is not a valid level. Levels: read, write, admin.`);
    if (path[0] !== '/') throw new Error(`Grant paths must start with /.`);
    grants.push({ path, level });
  }
  return grants;
}

async function loadUsers() {
  const target = $('user-list');
  target.replaceChildren(loadingRow());

  try {
    const users = await API.users();
    target.replaceChildren();
    if (!users.length) target.append(emptyRow('No users yet.'));

    for (const u of users) target.append(makeUserCard(u));
  } catch (err) {
    target.replaceChildren(emptyRow(err.message));
  }
}

function loadingRow() {
  const d = document.createElement('p');
  d.className = 'muted';
  d.textContent = 'Loading…';
  return d;
}

function emptyRow(msg) {
  const d = document.createElement('p');
  d.className = 'muted';
  d.textContent = msg;
  return d;
}

function makeUserCard(u) {
  const card = document.createElement('div');
  card.className = 'user';

  const head = document.createElement('div');
  head.className = 'user-head';

  const name = document.createElement('span');
  name.className = 'user-name';
  name.textContent = u.username;

  head.append(name);

  if (u.admin) head.append(badge('admin', ''));
  if (u.disabled) head.append(badge('disabled', 'warn'));
  if (u.must_change_password) head.append(badge('must reset', 'warn'));

  card.append(head);

  const list = document.createElement('ul');
  list.className = 'user-grants';
  const grants = u.admin
    ? [{ path: '/', level: 'admin' }]
    : (u.grants && u.grants.length ? u.grants : [{ path: '—', level: 'none' }]);

  for (const g of grants) {
    const li = document.createElement('li');
    const path = document.createElement('code');
    path.textContent = g.path;
    const level = document.createElement('span');
    level.textContent = g.level;
    li.append(path, level);
    list.append(li);
  }
  card.append(list);

  const actions = document.createElement('div');
  actions.className = 'user-actions';

  actions.append(
    actionButton('Edit access', () => editGrants(u)),
    actionButton('Set password', () => resetPassword(u)),
    actionButton(u.disabled ? 'Enable' : 'Disable', () => toggleUser(u)),
  );

  // Never offer to delete yourself: that is a fast way to lock yourself out.
  if (u.id !== state.user.id) {
    actions.append(actionButton('Delete', () => deleteUser(u)));
  }
  card.append(actions);
  return card;
}

function badge(text, kind) {
  const b = document.createElement('span');
  b.className = `badge${kind ? ' ' + kind : ''}`;
  b.textContent = text;
  return b;
}

function actionButton(label, onClick) {
  const b = document.createElement('button');
  b.type = 'button';
  b.textContent = label;
  b.addEventListener('click', onClick);
  return b;
}

async function editGrants(u) {
  const text = await promptSheet({
    title: `Access for ${u.username}`,
    text: 'One rule per line: <path> <level>. Levels: read, write, admin.',
    label: 'Rules',
    value: grantsToText(u.grants),
    ok: 'Save',
    textarea: true,
  });
  if (text === null) return;

  let grants;
  try {
    grants = textToGrants(text);
  } catch (err) {
    return toast(err.message, 'err');
  }

  try {
    await API.updateUser(u.id, { grants });
    toast('Access updated');
    loadUsers();
  } catch (err) {
    toast(err.message, 'err');
  }
}

async function resetPassword(u) {
  const pw = await promptSheet({
    title: `New password for ${u.username}`,
    text: 'They must change it after signing in. Minimum 8 characters.',
    label: 'Password',
    ok: 'Set password',
  });
  if (!pw) return;
  if (pw.length < 8) return toast('Password must be at least 8 characters.', 'err');

  try {
    await API.resetPassword(u.id, { password: pw });
    toast('Password set');
  } catch (err) {
    toast(err.message, 'err');
  }
}

async function toggleUser(u) {
  try {
    await API.updateUser(u.id, { disabled: !u.disabled });
    toast(u.disabled ? 'User enabled' : 'User disabled');
    loadUsers();
  } catch (err) {
    toast(err.message, 'err');
  }
}

async function deleteUser(u) {
  const ok = await confirmSheet(`Delete ${u.username}?`, 'They will be signed out immediately.', 'Delete');
  if (!ok) return;
  try {
    await API.deleteUser(u.id);
    toast('User deleted');
    loadUsers();
  } catch (err) {
    toast(err.message, 'err');
  }
}

async function addUser() {
  const name = await promptSheet({ title: 'Username', label: 'Username', ok: 'Next' });
  if (!name) return;

  const pw = await promptSheet({ title: `Password for ${name}`, label: 'Password (min 8 characters)', ok: 'Create' });
  if (!pw) return;
  if (pw.length < 8) return toast('Password must be at least 8 characters.', 'err');

  try {
    await API.createUser({ username: name, password: pw, admin: false, grants: [] });
    toast('User created');
    loadUsers();
  } catch (err) {
    toast(err.message, 'err');
  }
}

// ---------------------------------------------------------------- theme ---

function applyTheme(mode) {
  document.documentElement.dataset.theme = mode;
  try { localStorage.setItem('fb-theme', mode); } catch { /* private mode */ }
  $('theme-label').textContent = mode;
}

function cycleTheme() {
  const order = ['auto', 'light', 'dark'];
  const current = document.documentElement.dataset.theme || 'auto';
  applyTheme(order[(order.indexOf(current) + 1) % order.length]);
}

// ----------------------------------------------------------------- auth ---

function showLogin() {
  el.app.hidden = true;
  el.pwchange.hidden = true;
  el.bootstrap.hidden = true;
  el.login.hidden = false;
  closePanels();
  $('login-user').focus();
}

function showBootstrap() {
  el.app.hidden = true;
  el.login.hidden = true;
  el.pwchange.hidden = true;
  el.bootstrap.hidden = false;
  $('boot-user').focus();
}

function showPasswordChange() {
  el.app.hidden = true;
  el.login.hidden = true;
  el.bootstrap.hidden = true;
  el.pwchange.hidden = false;
  $('pw-cur').focus();
}

function showApp(user) {
  state.user = user;
  el.login.hidden = true;
  el.bootstrap.hidden = true;
  el.pwchange.hidden = true;
  el.app.hidden = false;
  closePanels();

  $('menu-user').textContent = user.username;
  $('mi-users').hidden = !user.admin;
  document.querySelectorAll('.admin-only').forEach((n) => { n.hidden = !user.admin; });

  // Honour a deep link such as /photos/2024 on a fresh load.
  navigate(currentPath());
}

async function doLogout() {
  try { await API.logout(); } catch { /* log out locally regardless */ }
  state.user = null;
  history.replaceState(null, '', location.pathname);
  showLogin();
}

// ----------------------------------------------------------------- boot ---

async function boot() {
  try { applyTheme(localStorage.getItem('fb-theme') || 'auto'); } catch { applyTheme('auto'); }

  try {
    const status = await API.status();
    if (status.needs_bootstrap) return showBootstrap();
  } catch {
    toast('Cannot reach the server.', 'err');
  }

  try {
    const me = await API.me();
    $('menu-version').textContent = `v${me.version} · up ${me.uptime}`;
    if (me.must_change_password) return showPasswordChange();
    showApp(me.user);
  } catch (err) {
    if (err.status === 401) return showLogin();
    toast(err.message, 'err');
    showLogin();
  }
}

// ---------------------------------------------------------------- wiring ---

function wire() {
  // Navigation
  $('btn-menu').addEventListener('click', () => openPanel(el.menu));
  $('btn-search').addEventListener('click', () => {
    openPanel(el.searchpane);
    $('search-input').focus();
  });
  el.scrim.addEventListener('click', closePanels);
  $('menu-close').addEventListener('click', closePanels);
  $('admin-close').addEventListener('click', closePanels);
  $('search-close').addEventListener('click', closePanels);

  // Browser back/forward between folders. popstate fires for both
  // pushState-created entries and real history navigation.
  window.addEventListener('popstate', () => {
    const target = currentPath();
    if (target !== state.path) navigate(target, { push: false });
  });

  $('mi-up').addEventListener('click', () => {
    closePanels();
    if (state.parent) navigate(state.parent);
  });
  $('mi-zip').addEventListener('click', () => {
    closePanels();
    startZip();
  });
  $('mi-mkdir').addEventListener('click', () => { closePanels(); doMkdir(); });
  $('mi-logout').addEventListener('click', doLogout);
  $('mi-theme').addEventListener('click', cycleTheme);
  $('mi-users').addEventListener('click', () => { openPanel(el.admin); loadUsers(); });
  $('mi-adduser').addEventListener('click', addUser);
  $('mi-pw').addEventListener('click', () => { closePanels(); showPasswordChange(); });

  $('search-input').addEventListener('input', onSearchInput);
  $('btn-fab').addEventListener('click', doFab);

  // Forms
  $('login-form').addEventListener('submit', onLogin);
  $('bootstrap-form').addEventListener('submit', onBootstrap);
  $('pw-form').addEventListener('submit', onPasswordChange);
}

/** The FAB uploads to the current folder; "New folder" lives in the drawer. */
async function doFab() {
  if (state.canWrite) await doUpload();
}

async function onLogin(e) {
  e.preventDefault();
  const btn = $('login-submit');
  const err = $('login-error');
  err.hidden = true;
  btn.disabled = true;
  btn.textContent = 'Signing in…';

  try {
    const data = await API.login({
      username: $('login-user').value,
      password: $('login-pass').value,
    });
    $('login-pass').value = '';
    if (data.must_change_password) return showPasswordChange();
    showApp(data.user);
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
}

async function onBootstrap(e) {
  e.preventDefault();
  const err = $('boot-error');
  const btn = $('bootstrap-form').querySelector('button[type=submit]');
  err.hidden = true;
  btn.disabled = true;

  try {
    await API.bootstrap({
      username: $('boot-user').value,
      password: $('boot-pass').value,
    });
    toast('Administrator created. Please sign in.');
    showLogin();
    $('login-user').value = $('boot-user').value;
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

async function onPasswordChange(e) {
  e.preventDefault();
  const err = $('pw-error');
  err.hidden = true;

  const cur = $('pw-cur').value;
  const next = $('pw-new').value;
  if (next !== $('pw-confirm').value) {
    err.textContent = 'The new passwords do not match.';
    err.hidden = false;
    return;
  }
  if (next.length < 8) {
    err.textContent = 'Password must be at least 8 characters.';
    err.hidden = false;
    return;
  }

  try {
    await API.changePassword({ current_password: cur, new_password: next });
    const me = await API.me();
    toast('Password updated');
    showApp(me.user);
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
}

// ---------------------------------------------------------------- install ---

// Android Chrome decides on its own whether to show its install banner, and
// frequently shows nothing at all. Rather than leave people hunting through
// the browser menu, capture the event and offer a button of our own. The
// event only fires once the browser is satisfied the app meets its install
// criteria, so showing the item is itself the signal.
let installPrompt = null;

function wireInstall() {
  const item = $('mi-install');

  // Already running as an installed app: nothing to offer.
  if (window.matchMedia('(display-mode: standalone)').matches) return;

  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault(); // suppress Chrome's own banner
    installPrompt = event;
    item.hidden = false;
  });

  window.addEventListener('appinstalled', () => {
    installPrompt = null;
    item.hidden = true;
    toast('Installed');
  });

  item.addEventListener('click', async () => {
    closePanels();

    if (!installPrompt) {
      // Either iOS, which never fires this event, or the criteria are not met.
      const ios = /iP(hone|ad|od)/.test(navigator.userAgent);
      toast(ios
        ? 'On iPhone: tap the Share button, then Add to Home Screen'
        : 'Use your browser menu and choose Install app or Add to Home screen');
      return;
    }

    installPrompt.prompt();
    const choice = await installPrompt.userChoice;
    installPrompt = null;
    item.hidden = true;
    if (choice.outcome === 'accepted') toast('Installing…');
  });
}

// Service worker keeps the shell available offline, which matters on a phone
// on patchy mobile data. API traffic is never cached: file listings are
// private and must not be stale.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {
      // Offline support is a bonus; failing to register is not fatal.
    });
  });
}

wire();
wireInstall();
boot();

// Exposed for debugging from a remote browser console.
window.__fb = { state, navigate, API };
