# Files

A private file browser for your own machine. One Go binary, one web app that
installs on iOS and Android like a native app, per-user folder permissions, and
no cloud service in the middle.

- **Browse and download from your phone** — install it to the home screen and it
  behaves like a normal app, with the system "Save to Files" sheet on iOS.
- **Multiple people, different folders** — each account sees only what you grant
  them, and never learns the names of folders they cannot open.
- **Reaches you over HTTPS** — a domain with automatic certificates, or a
  Tailscale/WireGuard VPN so nothing is exposed to the internet at all.
- **Reads nothing outside one directory** — enforced for every request,
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

With Docker:

```bash
git clone https://github.com/rackhaven/FileBrowser
cd FileBrowser

cp deploy/.env.example .env
$EDITOR .env              # set FB_ADMIN_PASSWORD

# Put your files in ./data/files, or point FB_ROOT at an existing share
docker compose -f deploy/docker-compose.yml up -d
```

Open `http://<your-server>:8080`, sign in as `admin`, and change the password
from the menu.

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
Open the URL, then the browser menu → **Install app** (or **Add to Home
screen**).

Either way, once installed it works offline for browsing the shell, and updates
itself the next time it has a connection.

---

## Giving people access

Access is a list of rules per user. Each rule is a folder and a level:

| Level   | Can do                                              |
| ------- | --------------------------------------------------- |
| `read`  | list folders, download files                         |
| `write` | all of `read`, plus upload, rename, delete           |
| `admin` | all of `write`, plus administer that subtree         |

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
the tunnel is already encrypted, plain HTTP on the tunnel is acceptable — but
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
| `-data`         | `FB_DATA_DIR`          | `/data`        | holds `users.json`                  |
| `-config`       | —                      | —              | YAML config file                    |
|                | `FB_SESSION_TTL`       | `168h`         | how long a sign-in lasts            |
|                | `FB_TRUST_PROXY_HEADERS` | `false`      | honour `X-Forwarded-Proto`          |
|                | `FB_TLS_CERT`/`FB_TLS_KEY` | —         | terminate TLS here instead          |
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
clamps to the root the way a chroot does, rather than escaping it.

**No information leak through listings.** A folder the user cannot open is
omitted from the listing entirely, rather than shown greyed out. Revealing that
`/photos/private` exists is itself a disclosure.

**Passwords** are hashed with argon2id at 64 MiB and 3 iterations. The hash is
never sent to a client; the struct that reaches the API has no field for it.

**Sessions** live on the server, not in the cookie. Signing out, changing a
password, disabling an account or an admin resetting a password all revoke
existing sessions immediately rather than waiting for a cookie to expire.
Cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` whenever the connection
is known to be HTTPS.

**Sign-in throttling**: 8 attempts per IP per 15 minutes. Failures are
indistinguishable in wording *and* in timing, so the endpoint cannot be used to
enumerate accounts.

**No self-service signup.** Accounts exist only if an administrator creates
them, so a server exposed to the internet cannot be joined by a stranger.

**Blast radius.** The container runs as uid 10001, with `read_only`, all
capabilities dropped and `no-new-privileges`. The systemd unit uses
`ProtectSystem=strict` with only two writable paths, and denies all addresses
except loopback.

### Things worth knowing

- **Sessions are in memory.** A restart signs everyone out. The user database
  survives; live sessions do not.
- **There is no second factor.** If you want it, put the service behind a VPN,
  or add an identity-aware proxy in front.
- **Rate limiting is per process and per IP.** A restart clears it. It is there
  to blunt guessing, not to be a hard control.
- **Uploads land in a temporary file and are renamed into place**, so an
  interrupted upload never leaves a truncated file that looks complete.
- **Nothing is encrypted at rest** beyond what your filesystem does. If the disk
  is stolen, the files are readable. Use disk encryption (LUKS, BitLocker) if
  that matters.

---

## How downloads work

Tapping a file hands it to the browser with a plain anchor. That is deliberate.

The obvious alternative — `fetch` the bytes in JavaScript and save a blob —
would have to hold the whole file in memory, so a 4 GB video fails, and on iOS
it offers no "Save to Files" sheet at all. Letting the browser stream it is both
lighter and is what produces the native picker.

Consequences worth knowing:

- Resuming an interrupted large download works, because the server supports
  `Range` requests (`206 Partial Content`).
- The browser owns the download, so its own UI shows progress and retry.
- Images and PDFs open inline instead of downloading, since the browser can
  display them.

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

### Tests

The suite leans on the filesystem rules, because that is where the risk is:

- `internal/fs/fs_test.go` — traversal, symlink escape, ACL resolution,
  listing visibility, symlink listing
- `internal/auth/auth_test.go` — hashing, the store, last-admin protection,
  concurrency
- `internal/server/server_test.go` — the HTTP surface end to end: auth
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
deploy/              Dockerfile, compose, systemd unit, Caddyfile, config sample
tools/               icon generator, PWA wiring checks, screenshots
```

---

## HTTP API

All routes are under the same origin and use the session cookie. JSON unless
noted.

**Auth**

| Method | Path | |
| --- | --- | --- |
| `GET` | `/api/status` | version, uptime, whether setup is needed (public) |
| `POST` | `/api/auth/login` | `{username, password}` → sets the session cookie |
| `POST` | `/api/auth/logout` | revokes the session |
| `GET` | `/api/auth/me` | current user |
| `POST` | `/api/auth/password` | `{current_password, new_password}` |
| `POST` | `/api/auth/bootstrap` | create the first admin; only while zero users exist |

**Files**

| Method | Path | |
| --- | --- | --- |
| `GET` | `/api/fs/list?path=/` | entries the user may see |
| `GET` | `/api/fs/info?path=/a.txt` | one entry |
| `GET`/`HEAD` | `/api/fs/download?path=/a.txt` | stream; supports `Range`, `?inline=1` |
| `PUT` | `/api/fs/upload?path=/dir&name=f.txt` | raw body streamed to disk |
| `POST` | `/api/fs/mkdir` | `{path, name}` |
| `POST` | `/api/fs/rename` | `{from, to_dir, new_name}` |
| `POST` | `/api/fs/delete?path=/a.txt` | recursive for folders |
| `GET` | `/api/fs/usage?path=/&depth=8` | `{files, dirs, bytes}` |

**Admin** — all require an administrator.

| Method | Path | |
| --- | --- | --- |
| `GET` | `/api/admin/users` | list accounts |
| `POST` | `/api/admin/users` | `{username, password, admin, grants}` |
| `PATCH` | `/api/admin/users/{id}` | `{admin?, disabled?, grants?}` |
| `DELETE` | `/api/admin/users/{id}` | remove |
| `POST` | `/api/admin/users/{id}/password` | `{password}`; forces a change |

A grant is `{path, level}` where `level` is `read`, `write` or `admin`.

---

## Licence

**GNU Affero General Public License v3.0 or later** — see [`LICENSE`](LICENSE).

AGPL rather than GPL because this is a network server. If you run a modified
version and let other people reach it over a network, you must offer them the
source of your version. That is why the app itself carries a **source code**
link in the menu: the licence requires the offer to be made to remote users, not
merely to whoever downloads a tarball.
