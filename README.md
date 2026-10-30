# Files

A private file browser for your own machine. One Go binary, one web app that
installs on iOS and Android like a native app, per-user folder permissions, and
no cloud service in the middle.

- **Browse and download from your phone**: install it to the home screen and it
  behaves like a normal app, with the system "Save to Files" sheet on iOS.
- **Multiple people, different folders**: each account sees only what you grant
  them, and never learns the names of folders they cannot open.
- **Reaches you over HTTPS**: a domain with automatic certificates, or a
  Tailscale/WireGuard VPN so nothing is exposed to the internet at all.
- **Reads nothing outside one directory**: enforced for every request,
  including administrators, including symlinks.

```
┌──────────────┐      HTTPS      ┌──────────┐      ┌──────────┐
│ phone / PWA  │ ──────────────▶ │  Caddy   │ ───▶ │  this    │ ──▶ /srv/files
│ or VPN only  │                 │ (or VPN) │      │ service  │
└──────────────┘                 └──────────┘      └──────────┘
```

---

## Contents

- [Quick start](#quick-start)
- [Installing it on your phone](#installing-it-on-your-phone)
- [Giving people access](#giving-people-access)
- [Reaching it from outside your network](#reaching-it-from-outside-your-network)
- [Managing users from the command line](#managing-users-from-the-command-line)
- [Configuration](#configuration)
- [Security notes](#security-notes)
- [How downloads work](#how-downloads-work)
- [Development](#development)
- [HTTP API](#http-api)
- [Layout](#layout)

---

## Quick start

The published image is `ghcr.io/rackhaven/filebrowser` (tags `vX.Y.Z` and
`latest`). It needs two mounts: your files, and a place for its database.

```bash
docker run -d --name filebrowser \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:size=64m \
  -p 8080:8080 \
  -v /srv/files:/srv/files \
  -v filebrowser-data:/data \
  -e FB_ADMIN_PASSWORD="$(openssl rand -base64 18)" \
  ghcr.io/rackhaven/filebrowser:latest

docker logs filebrowser      # prints the generated admin password once
```

Or with compose, which pins, restarts and logs-rotates for you:

```bash
git clone https://github.com/rackhaven/FileBrowser
cd FileBrowser

cp deploy/.env.example deploy/.env
$EDITOR deploy/.env          # set FB_ADMIN_PASSWORD, maybe FB_TAG and FB_ROOT

docker compose -f deploy/docker-compose.yml up -d
```

The compose file runs the published image by default; `docker compose build`
swaps in a locally built one from the checked-out tree, which is what an
air-gapped deployment does.

Open `http://<your-server>:8080`, sign in as `admin`, and change the password
from the menu. Also from the menu: the theme, the devices signed in, and the
trash drawer.

Without Docker, on any Linux box or Raspberry Pi:

```bash
go build -o filebrowser ./cmd/filebrowser    # or download a release binary

sudo useradd -r -s /usr/sbin/nologin filebrowser
sudo install -m 0755 filebrowser /usr/local/bin/
sudo mkdir -p /srv/files /var/lib/filebrowser
sudo chown filebrowser:filebrowser /var/lib/filebrowser

FB_ADMIN_USER=admin FB_ADMIN_PASSWORD="$(openssl rand -base64 18)" \
  ./filebrowser serve --root /srv/files --data /var/lib/filebrowser
```

On first start with no accounts, the server generates a strong random password
and prints it **once**. Set `FB_ADMIN_USER` and `FB_ADMIN_PASSWORD` if you would
rather choose it yourself.

> The first admin's password is the only thing printed to the log. Capture it,
> then sign in and change it.

---

## Installing it on your phone

The web app is a PWA: it has a manifest, icons, and a service worker, so both
platforms offer to install it.

**iPhone / iPad (Safari)**
Open the URL, tap <kbd>Share</kbd>, then **Add to Home Screen**. It then opens
full screen with no browser chrome, and downloads use the system *Save to Files*
picker.

**Android (Chrome)**
Open the URL. Either use the browser menu → **Install app** (or **Add to Home
screen**), or open the app's own menu (☰) → **Install app**.

That second option exists because Chrome decides for itself whether to show an
install banner, and often shows nothing at all. The app listens for the same
`beforeinstallprompt` event and only reveals the menu item once Chrome has
confirmed the app meets its install criteria, so its presence means it will
work. There is deliberately no such button on iOS: Safari has no programmatic
install, so the Share route is the only one.

Note that installation requires **HTTPS**. If you are reaching the server over
plain HTTP (a `http://100.x.y.z:8080` address, say), Chrome will refuse to
install it. `tailscale serve` or a domain with Caddy gives you a real
certificate.

Either way, once installed it works offline for browsing the shell, and updates
itself the next time it has a connection.

---

## Giving people access

Access is a list of rules per user. Each rule is a folder and a level:

| Level   | Can do                                              |
| ------- | --------------------------------------------------- |
| `read`  | list folders, download files                         |
| `write` | all of `read`, plus upload, rename, copy, delete     |

Earlier versions also offered an `admin` level for grants. It never granted
more than `write`, so databases that still carry one load it as `write` and
save it that way; new rules are refused with a pointer to the account's
administrator flag instead.

A rule applies to the folder **and everything under it**. The most specific
rule wins, so this is exactly what you would expect:

```
/            read      everyone can see the whole tree
/photos      write     photos is shared more openly
/photos/private  read  ...except this one folder, read-only
```

An `admin` account ignores rules entirely and sees everything inside the root.

Rules on a narrower path still let a user reach a deep folder: someone with
only `/photos/private` can still open `/photos` to get there, they just see
nothing else. The UI marks those intermediate folders so it is not confusing.

A narrower rule also survives whatever happens to the folder around it. With
the rules above, someone holding write on `/photos` still cannot delete,
move or rename `/photos` itself, because that would carry `/photos/private`
off with it; replacing a file needs write on that file, not just on its
folder. Everything else in `/photos` stays theirs to change.

**Deletes go to a trash, not off the disk.** Removing a file or folder moves it
into a reserved `.trash` directory with a record of where it came from, who
deleted it and when. **Menu → Deleted items** lists what you can act on:
anything you deleted, or anything deleted from a folder you can write to, with
**Restore** and **Erase** per item. Erase additionally needs write over
everything the item held, so a folder an administrator deleted with a
read-only rule inside it can be restored by its writers but only erased by
an administrator. Rescue a whole subtree later: restoring recreates any
folders that went with it. Erasing every item at once is an
administrator action, and nothing in the trash survives being erased. The
trash lives at the top of the root, and deleting from a disk mounted inside
the root still works: the item is copied into the trash in full, then
removed. That is slower than the usual instant move and needs room on the
root's own disk, and an item holding something that cannot be copied (a
fifo or device node) is refused whole rather than moved in part.

**Deleted items age out.** By default entries leave the trash after 30 days
(`trash_ttl`), erasing item and record quietly in the background, once a day.
The trash is a safety net against a finger slip, not a second copy of your
files or a substitute for backups. Set the window to `0s` to disable:
nothing is erased by the server, only by hands.

**Administrators cannot remove, disable or demote the last remaining
administrator**, so you cannot lock yourself out.

You can edit everything from the in-app **menu → Manage users**, or with the CLI
(below).

---

## Reaching it from outside your network

Pick whichever suits you. They are independent; you can combine them.

### Option A: a domain with automatic HTTPS

The normal choice if you want access from anywhere without being on your
network.

1. Point a DNS `A` record at the machine.
2. Put [Caddy](https://caddyserver.com) in front. It obtains and renews a
   Let's Encrypt certificate on its own.

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile   # edit the hostname
sudo systemctl reload caddy
```

Then set these on the service:

```yaml
trust_proxy_headers: true   # so the session cookie is marked Secure
```

Bind the service to `127.0.0.1:8080` so it is only reachable through Caddy.

### Option B: Tailscale, with HTTPS and no open ports

Tailscale gives every device a private address and a real certificate. Nothing
is published to the internet, so there is nothing to attack.

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# HTTPS on the tailnet only, with a valid certificate
sudo tailscale serve --bg http://127.0.0.1:8080
```

`tailscale serve` prints a `https://<machine>.<tailnet>.ts.net` URL. Install the
Tailscale app on your phone and use that URL. Only devices on your tailnet can
reach it.

For plain HTTP without a certificate:

```bash
sudo tailscale serve --bg http://127.0.0.1:8080   # then use the http:// tailnet URL
```

### Option C: WireGuard

No extra software, and the connection is yours to build.

```bash
sudo wg-quick up wg0     # on the server
# install the WireGuard app on your phone, import the .conf
```

Then browse the server's tunnel address (e.g. `https://10.0.0.1:8080`). Because
the tunnel is already encrypted, plain HTTP on the tunnel is acceptable, but
browsers will warn about the self-signed certificate, so prefer `tailscale
serve` if you want a certificate the browser trusts.

### Which one?

| You want                                    | Use      |
| ------------------------------------------- | -------- |
| Access from anywhere, no VPN app on phones  | A        |
| Nothing exposed to the internet            | B or C   |
| Least setup                                 | C        |
| A certificate the browser trusts           | A or B   |

Whatever you choose, keep the service on `127.0.0.1` unless it is genuinely
supposed to be directly reachable, and put a firewall in front of it.

---

## Managing users from the command line

Useful for scripting and for when you lock yourself out.

```bash
# List accounts and their grants
filebrowser user list

# Create a user (prompts for the password; it is never taken as an argument)
filebrowser user add alice
filebrowser user add --grant /photos:read,/docs:write bob
filebrowser user add --admin carol

# Reset a password. The user must choose a new one at next sign-in.
filebrowser user passwd alice

# Remove an account
filebrowser user rm bob
```

Flags may go before or after the username.

Point it at the same database the server uses:

```bash
filebrowser user list --data /var/lib/filebrowser   # or set FB_DATA_DIR
```

Running these while the server is up is safe. Both processes coordinate
through an advisory lock (`users.json.lock`) and the server re-reads the
database before every change, so a CLI edit cannot interleave with, or be
silently overwritten by, a live server's own write. The server also notices
CLI edits on every request: a removed account is signed out at its next
request, and after `user passwd` the old password stops working and any
device still signed in can do nothing but choose a new one. The lock is only
held while a change is written, never while the CLI waits for you to type.
The one exception is Windows, where the lock is a no-op: do CLI maintenance
while the server is stopped.

---

## Configuration

Every option can be set three ways. Later entries win:

1. a YAML config file, `-config`
2. environment variables, `FB_*`
3. command-line flags

See [`deploy/config.example.yaml`](deploy/config.example.yaml) for a commented
file.

| Flag            | Environment            | Default        | Meaning                             |
| --------------- | ---------------------- | -------------- | ----------------------------------- |
| `-listen`       | `FB_LISTEN`            | `0.0.0.0:8080` | bind address                        |
| `-root`         | `FB_ROOT`              | `/srv/files`   | the one directory that is exposed   |
| `-data`         | `FB_DATA_DIR`          | `/data`        | holds `users.json` and `sessions.json` |
| `-config`       |                        | none           | YAML config file                    |
|                | `FB_SESSION_TTL`       | `168h`         | how long a sign-in lasts            |
|                | `FB_TRASH_TTL`         | `720h`         | deleted items leave the trash after this; `0s` keeps them |
|                | `FB_TRUST_PROXY_HEADERS` | `false`      | honour `X-Forwarded-Proto` and `X-Forwarded-For` |
|                | `FB_MAX_UPLOAD_BYTES`  | `34359738368`  | largest upload, in bytes            |
|                | `FB_THUMB_CACHE`       | `<data>/thumbs` | where generated image previews live; follows `-data` unless set |
|                | `FB_TLS_CERT`/`FB_TLS_KEY` | none      | terminate TLS here instead          |
|                | `FB_LOG_LEVEL`         | `info`         | `debug`, `info`, `warn`, `error`    |
|                | `FB_ADMIN_USER`        | `admin`        | first-run account name              |
|                | `FB_ADMIN_PASSWORD`    | generated      | first-run password                  |

---

## Security notes

What the design actually guarantees, rather than what it merely tries to do:

**Path containment.** Every request resolves its path through one function that
rejects traversal (`..`, absolute paths, backslashes, encoded separators) and
then re-checks containment *after* following symlinks. A symlink inside the
root that points at `/etc` is neither listable nor readable. `..` at the top
clamps to the root the way a chroot does, rather than escaping it. On Linux
the open that finally touches the bytes goes through `openat2` with the root
directory as the kernel's anchor: even a race that swaps in a symlink after the
resolve cannot walk outside, and `/proc`-style magic links are refused
outright. Links inside the tree work when their target is written relative to
the link, the form that survives the tree being anywhere; a link that names
the root by its absolute location on disk cannot be followed, because the
kernel re-anchors targets inside the root, and it opens as not found.

**Links lend no access.** A symlink is followed only when the user could
reach its target on their own: through a link, a user holds the weaker of
their level where the link sits and their level where it points. A link in a
shared folder that points into a folder the user has no rule for is hidden
from their listings, searches, zips and copies, and opens as not found.
Deleting or renaming a link moves the link itself, so only the folder it
sits in matters.

**No information leak through listings.** A folder the user cannot open is
omitted from the listing entirely, rather than shown greyed out. Revealing that
`/photos/private` exists is itself a disclosure.

**Passwords** are hashed with argon2id at 64 MiB and 3 iterations. The hash is
never sent to a client; the struct that reaches the API has no field for it.

**Sessions** live on the server, not in the cookie. Signing out, changing a
password, disabling an account or an admin resetting a password all revoke
existing sessions immediately rather than waiting for a cookie to expire.
Cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` whenever the connection
is known to be HTTPS. On top of that, state-changing requests are refused when
the browser announces a foreign `Origin` or `Sec-Fetch-Site`.

**Sign-in throttling**: 8 attempts per IP per 15 minutes. Failures are
indistinguishable in wording *and* in timing (every attempt is hashed,
including ones for usernames that do not exist), so the endpoint cannot be
used to enumerate accounts. A process-wide gate caps how many passwords are
hashed at the same moment, bounding the memory that hashing consumes when
attempts arrive from many addresses at once; changing a password and the
admin paths that set one share it. Wrong current passwords on the change
form are throttled per account, 8 per 15 minutes, so a stolen cookie is not
a free way to guess the password behind it.

**No self-service signup.** Accounts exist only if an administrator creates
them, so a server exposed to the internet cannot be joined by a stranger.

**Blast radius.** The container runs as uid 10001, with `read_only`, all
capabilities dropped and `no-new-privileges`. The systemd unit uses
`ProtectSystem=strict` with only two writable paths, and denies all addresses
except loopback.

### Things worth knowing

- **Sessions survive a restart.** They live on the server and are written to
  `sessions.json` in the data directory, beside the user database, on every
  change. Only token hashes are stored, never the live tokens themselves, so
  the file says nothing a stolen cookie needs. Delete it (or lose the whole
  data directory) and every device is signed out on the spot.
- **You can sign devices out yourself, one at a time.** The menu lists every
  live session of your account with when it was created and last used, and you
  can revoke any of the others. A stolen cookie dies as soon as you click.
- **There is no second factor.** If you want it, put the service behind a VPN,
  or add an identity-aware proxy in front.
- **Rate limiting is per process and per IP.** A restart clears it. It is there
  to blunt guessing, not to be a hard control. IPv6 clients are limited per
  /64, since one subscriber is routinely handed a whole /64 and could
  otherwise rotate through it for fresh attempts. When `trust_proxy_headers` is
  set, the address that is limited and logged comes from `X-Forwarded-For`,
  which is why the flag should only be on behind a proxy that overwrites that
  header with the client's address rather than appending to it (the sample
  Caddyfile does exactly that).
- **Uploads land in a temporary file and are renamed into place**, so an
  interrupted upload never leaves a truncated file that looks complete. The
  rename claims the name atomically (on Linux), so a file that appears while
  an upload is still streaming is never replaced by it; the late upload
  answers 409 instead. Moves and restores are no-replace the same way.
- **Copies behave the same way**, and a copy is a create, not a replace: an
  app already sitting at the destination refuses to be overwritten. Folder
  copies walk the tree while links and reserved names behave exactly as in a
  listing, so nothing hidden can leak into a duplicate.
- **Nothing is encrypted at rest** beyond what your filesystem does. If the disk
  is stolen, the files are readable. Use disk encryption (LUKS, BitLocker) if
  that matters.

---

## How downloads work

Tapping a file hands it to the browser with a plain anchor. That is deliberate.

The obvious alternative, `fetch` the bytes in JavaScript and save a blob,
would have to hold the whole file in memory, so a 4 GB video fails, and on iOS
it offers no "Save to Files" sheet at all. Letting the browser stream it is both
lighter and is what produces the native picker.

Consequences worth knowing:

- Resuming an interrupted large download works, because the server supports
  `Range` requests (`206 Partial Content`).
- The browser owns the download, so its own UI shows progress and retry.
- Images and PDFs open inline instead of downloading, since the browser can
  display them.
- A whole folder can come down as one zip: use "Download this folder as zip"
  in the menu. The archive streams with constant memory, contains only entries
  the signed-in user may read, and skips unfinished uploads. Symlinks are
  followed under the same rules as listings, and a folder reachable by two
  names is archived once, so a link back up the tree cannot loop. A download
  whose reader stops accepting bytes for a minute is cut off, so a phone that
  lost signal does not hold the server's archive slot forever.
- Search in the magnifier drawer runs on the server and reaches everything
  below the folder you are in, stopping at 300 results; the query box in the
  main pane still narrows the current folder as you type.
- Image previews are refused for pictures that would take more than 256 MiB
  to decode (about 64 megapixels of plain RGBA): the row keeps its icon, and
  the file still opens and downloads normally.

Uploads use `XMLHttpRequest` rather than `fetch`, purely because it is the only
way to report progress.

---

## Development

```bash
make dev          # run on :8080 against ./data/files
make test         # go vet + unit tests
make check        # fmt + vet + tests + PWA wiring checks
make test-race    # tests under the race detector (needs cgo)
make build-all    # static binaries for linux, darwin, windows
make image        # build the container (tests run inside the build)
```

### Releases

A release is a tag. Push a `v`-prefixed tag and the release workflow
(`.github/workflows/release.yml`) runs the test suite, vet and formatting
again at the tag, then builds static binaries for `linux`, and macOS and
Windows (`amd64` and `arm64` on linux and macOS), each with `CGO_ENABLED=0`,
`-trimpath` and the tag stamped into `filebrowser version`. `gh` publishes a
GitHub release with the binaries and a `sha256sum` manifest, and a second job
pushes the container image to `ghcr.io` under the same tag plus `latest`,
assembled by the same Dockerfile CI uses, so the tests run inside the image
build too. The image is published for `linux/amd64` and `linux/arm64`: the
suite runs once on the builder and each platform gets its own build step, so
roughly the same two minutes produce both.

### Tests

The suite leans on the filesystem rules, because that is where the risk is:

- `internal/fs/fs_test.go`: traversal, symlink escape, ACL resolution,
  listing visibility, symlink listing
- `internal/auth/auth_test.go`: hashing, the store, last-admin protection,
  concurrency
- `internal/server/server_test.go`: the HTTP surface end to end: auth
  enforcement, per-user grants, range requests, upload, admin APIs

Some of those cases only exercise symlinks on Linux, so **the container build
runs the suite**, and CI runs it under `-race`. A plain `go test` on Windows
silently skips the symlink tests; do not trust a green Windows run on its own.

### PWA tooling

The front end is three files with no build step, so a few small Node scripts
check the things a compiler cannot:

```bash
node tools/check-wiring.mjs   # ids/classes app.js uses exist in index.html/CSS
node tools/gen-icons.mjs      # regenerate PWA icons
node tools/screenshot.mjs <sessionCookie> out/   # CDP screenshots
```

### Layout

```
cmd/filebrowser/     CLI entry point, serve + user subcommands
internal/auth/       argon2id hashing, user database, server-side sessions
internal/fs/         ACL enforcement and symlink-safe path resolution
internal/server/     HTTP handlers, middleware, routing
web/assets/          the PWA (html, css, js, service worker, icons)
Dockerfile           container build; the test suite runs inside it
deploy/              compose, systemd unit, Caddyfile, config sample
tools/               icon generator, PWA wiring checks, screenshots
```

---

## HTTP API

All routes are under the same origin and use the session cookie. JSON unless
noted.

**Auth**

| Method | Path | |
| --- | --- | --- |
| `GET` | `/api/status` | whether setup is needed (public; no build details) |
| `POST` | `/api/auth/login` | `{username, password}` → sets the session cookie |
| `POST` | `/api/auth/logout` | revokes the session |
| `GET` | `/api/auth/me` | current user, plus version and uptime |
| `GET` | `/api/auth/sessions` | live sessions of this account: id, times, a short token hint, which is current |
| `DELETE` | `/api/auth/sessions?id=` | revoke one of your other sessions; the current one refuses, sign out instead |
| `POST` | `/api/auth/password` | `{current_password, new_password}` |
| `POST` | `/api/auth/bootstrap` | create the first admin; only while zero users exist |

**Files**

| Method | Path | |
| --- | --- | --- |
| `GET` | `/api/fs/list?path=/` | entries the user may see; add `limit=` and `offset=` to page through big folders |
| `GET` | `/api/fs/search?path=/&q=term` | name matches below `path`, capped at 300, ACL-filtered |
| `GET` | `/api/fs/info?path=/a.txt` | one entry |
| `GET` | `/api/fs/thumb?path=/a.jpg` | small preview; weak `ETag`, so revalidation happens for free |
| `GET`/`HEAD` | `/api/fs/download?path=/a.txt` | stream; supports `Range`, `?inline=1` |
| `GET` | `/api/fs/zip?path=/docs` | whole folder as a zip, streamed; same ACL rules as listings |
| `PUT` | `/api/fs/upload?path=/dir&name=f.txt` | raw body streamed to disk; an existing file refuses (409) unless `overwrite=1` |
| `POST` | `/api/fs/mkdir` | `{path, name}` |
| `POST` | `/api/fs/rename` | `{from, to_dir, new_name, overwrite}`; an existing file refuses (409) unless `overwrite` is set, and directories are never replaced |
| `POST` | `/api/fs/copy` | `{from, to_dir, name}`; a sibling duplicate. `to_dir` and `name` are optional: the copy then lands beside the source, under the name the UI proposes. An existing destination refuses (409), never replaced |
| `POST` | `/api/fs/delete?path=/a.txt` | recursive for folders; the entry moves to the trash, see below |
| `GET` | `/api/fs/trash` | deleted items the caller may act on, `{entries}`; each says `can_restore` and `can_erase` |
| `POST` | `/api/fs/restore` | `{name}`; put a trashed entry back where it came from |
| `DELETE` | `/api/fs/trash?name=` | erase one trashed entry; with no `name`, admin-only wipe of the whole trash |
| `GET` | `/api/fs/usage?path=/&depth=8` | `{files, dirs, bytes}` |

**Admin**: all require an administrator.

| Method | Path | |
| --- | --- | --- |
| `GET` | `/api/admin/users` | list accounts |
| `POST` | `/api/admin/users` | `{username, password, admin, grants}` |
| `PATCH` | `/api/admin/users/{id}` | `{admin?, disabled?, grants?}` |
| `DELETE` | `/api/admin/users/{id}` | remove |
| `POST` | `/api/admin/users/{id}/password` | `{password}`; forces a change |

A grant is `{path, level}` where `level` is `read` or `write`. Administration
is not a grant level: it is the account's `admin` flag.

---

## Licence

**GNU Affero General Public License v3.0 or later**. See [`LICENSE`](LICENSE).

AGPL rather than GPL because this is a network server. If you run a modified
version and let other people reach it over a network, you must offer them the
source of your version. That is why the app itself carries a **source code**
link in the menu: the licence requires the offer to be made to remote users, not
merely to whoever downloads a tarball.
