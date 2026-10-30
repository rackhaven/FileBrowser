// Copyright (C) 2026 the Files authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package server

import (
	"context"
	"encoding/json"
	"io"
	stdfs "io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rackhaven/filebrowser/internal/auth"
	"github.com/rackhaven/filebrowser/internal/fs"
)

type ctxKey string

const (
	ctxUser  ctxKey = "user"
	ctxToken ctxKey = "token"
	ctxSess  ctxKey = "session"
)

const sessionCookie = "fb_session"

// Config is the subset of configuration the HTTP layer needs.
type Config struct {
	TrustProxyHeaders bool
	SessionTTL        time.Duration
	// MaxUploadBytes caps an upload request body. Zero falls back to the
	// server default so a caller that forgets the field stays safe.
	MaxUploadBytes int64
	// ThumbCache points at the generated-preview directory; empty disables
	// thumbnails. A path that cannot be created only demotes thumbnails to
	// the uncacheable path, it never takes the server down.
	ThumbCache string
	// DataDir is where stores live, so the health endpoint can prove the
	// process can still write where it must. Empty skips that check, which
	// is for tests and embedded use; main always sets it.
	DataDir string
}

// defaultMaxUpload is used whenever no usable cap is supplied. It is the
// same 32 GiB baked into config.Default, restated here so the HTTP layer
// stays safe even when a caller constructs Options by hand (tests do).
const defaultMaxUpload = 32 << 30

// Server wires the user store, sessions, filesystem view and HTTP routes.
type Server struct {
	cfg      Config
	users    *auth.Store
	sessions *auth.Sessions
	files    *fs.FS
	static   stdfs.FS
	limiter  *rateLimiter
	// hashGate bounds concurrent password hashing: sign-in, password
	// changes, and the admin and bootstrap paths that set one. Each hash
	// costs 64 MiB of argon2id memory, so the gate caps that cost no matter
	// how many requests arrive at once, signed in or not.
	hashGate chan struct{}
	// workGate bounds concurrent heavy interactive work: image decodes,
	// search and usage walks. Without it, N authenticated requests in
	// parallel cost N times the worst handler's peak memory, which is how a
	// bored user takes a server to its knees without ever touching upload
	// or login.
	workGate chan struct{}
	// bulkGate is workGate for jobs measured in minutes rather than
	// milliseconds: zip streams and copies. Kept apart so a few large
	// archives on slow connections never queue a thumbnail behind them.
	bulkGate  chan struct{}
	started   time.Time
	version   string
	log       *slog.Logger
	maxUpload int64
}

// Options configures New.
type Options struct {
	Config   Config
	Users    *auth.Store
	Sessions *auth.Sessions
	FS       *fs.FS
	// Static is the embedded PWA asset tree.
	Static  stdfs.FS
	Version string
	Logger  *slog.Logger
}

// New builds a Server. Any nil field is replaced with a safe default so a
// misconfigured deployment fails loudly at request time instead of panicking.
func New(opt Options) *Server {
	logger := opt.Logger
	if logger == nil {
		logger = slog.Default()
	}
	sessions := opt.Sessions
	if sessions == nil {
		sessions = auth.NewSessions(opt.Config.SessionTTL)
	}
	uploadMax := opt.Config.MaxUploadBytes
	if uploadMax <= 0 {
		uploadMax = defaultMaxUpload
	}
	if opt.FS != nil && opt.Config.ThumbCache != "" {
		if err := opt.FS.SetThumbCache(opt.Config.ThumbCache); err != nil {
			logger.Warn("thumbnail cache unavailable; previews regenerate on each request",
				"err", err)
		}
	}
	return &Server{
		cfg:       opt.Config,
		users:     opt.Users,
		sessions:  sessions,
		files:     opt.FS,
		static:    opt.Static,
		limiter:   newRateLimiter(8, 15*time.Minute),
		hashGate:  make(chan struct{}, 4),
		workGate:  make(chan struct{}, 4),
		bulkGate:  make(chan struct{}, 4),
		started:   time.Now(),
		version:   opt.Version,
		log:       logger,
		maxUpload: uploadMax,
	}
}

func (s *Server) logf(msg string, args ...any) {
	s.log.Info(msg, args...)
}

func (s *Server) logError(msg string, args ...any) {
	s.log.Error(msg, args...)
}

// workSlot takes one of the few heavy-work slots, waiting until one frees.
// It returns the release function, which handlers defer, and false when the
// client went away first: there is nobody left to answer, and a request
// that is no longer wanted must not keep its place in the queue.
func (s *Server) workSlot(r *http.Request) (func(), bool) {
	return takeSlot(r, s.workGate)
}

// bulkSlot is workSlot for zip streams and copies.
func (s *Server) bulkSlot(r *http.Request) (func(), bool) {
	return takeSlot(r, s.bulkGate)
}

func takeSlot(r *http.Request, gate chan struct{}) (func(), bool) {
	select {
	case gate <- struct{}{}:
		return func() { <-gate }, true
	case <-r.Context().Done():
		return nil, false
	}
}

// requireAuth wraps a handler so it only runs for a logged-in user.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		tok := cookie.Value

		sess := s.sessions.Lookup(tok)
		if sess == nil {
			s.clearSessionCookie(w, r) // stop the browser resending a dead token
			writeError(w, http.StatusUnauthorized, "session expired, please sign in again")
			return
		}

		user, err := s.users.Get(sess.UserID)
		if err != nil || user.Disabled {
			// Account deleted or disabled while this session was live.
			if endErr := s.sessions.End(tok); endErr != nil {
				s.logError("could not end a dead session", "err", endErr)
			}
			s.clearSessionCookie(w, r)
			writeError(w, http.StatusUnauthorized, "account is no longer active")
			return
		}

		// A forced password change means exactly that: until the password
		// has been rotated (or signed out from), the only things this
		// session may do are authentication housekeeping, so a temporary
		// password an admin handed out is never a working key to the rest
		// of the API. The client reacts to the marker and walks the user
		// into the change-password screen.
		if user.MustChangePassword && !isAuthHousekeeping(r.URL.Path) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                "change your password before continuing",
				"must_change_password": true,
			})
			return
		}

		s.sessions.Touch(tok) // sliding expiry for active users
		ctx := context.WithValue(r.Context(), ctxUser, user)
		ctx = context.WithValue(ctx, ctxToken, tok)
		ctx = context.WithValue(ctx, ctxSess, sess)
		next(w, r.WithContext(ctx))
	}
}

// isAuthHousekeeping reports whether path is one of the few authenticated
// endpoints a session with a forced password change may still use.
func isAuthHousekeeping(path string) bool {
	return path == "/api/auth/password" ||
		path == "/api/auth/logout" ||
		path == "/api/auth/me" ||
		path == "/api/auth/sessions" ||
		path == "/api/status"
}

// requireAdmin additionally insists on the admin flag.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r.Context()).Admin {
			writeError(w, http.StatusForbidden, "administrator access required")
			return
		}
		next(w, r)
	})
}

// userFrom pulls the authenticated user out of the context.
func userFrom(ctx context.Context) *auth.User {
	u, _ := ctx.Value(ctxUser).(*auth.User)
	return u
}

// sessionFrom pulls the caller's own live session out of the context.
func sessionFrom(ctx context.Context) *auth.Session {
	s, _ := ctx.Value(ctxSess).(*auth.Session)
	return s
}

// allowHash acquires one of the few slots for password hashing, or gives up
// after a short wait and closes with 503. On success the caller must release
// the slot with <-s.hashGate.
//
// Every sign-in attempt is hashed, including attempts against usernames that
// do not exist, which is what keeps unknown users and wrong passwords
// indistinguishable in timing. That makes each attempt cost about 64 MiB of
// memory; the per-IP throttle bounds one address, and this gate bounds the
// whole process when many addresses arrive at once. Every other handler that
// hashes takes a slot here too, so a signed-in user cannot do the same
// damage through the password form.
func (s *Server) allowHash(w http.ResponseWriter) bool {
	select {
	case s.hashGate <- struct{}{}:
		return true
	default:
	}
	// Slots busy. Wait briefly so an honest burst of sign-ins queues rather
	// than erroring, then refuse politely.
	select {
	case s.hashGate <- struct{}{}:
		return true
	case <-time.After(3 * time.Second):
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, "the server is busy, try again shortly")
		return false
	}
}

// stallLimit is how long a streamed response may go without the client
// accepting a byte before the server gives up on it. A variable only so
// tests need not wait a minute.
var stallLimit = 60 * time.Second

// stallGuard extends the connection's write deadline before every write, so
// a stream to a reader that stopped reading fails after stallLimit instead
// of holding its slot forever, while a slow but moving one runs as long as
// it needs. There is no server-wide write timeout for exactly that reason.
type stallGuard struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func newStallGuard(w http.ResponseWriter) *stallGuard {
	return &stallGuard{w: w, rc: http.NewResponseController(w)}
}

func (g *stallGuard) Write(p []byte) (int, error) {
	// ErrNotSupported only means the writer cannot time out; streaming
	// still works, it just loses the guard.
	_ = g.rc.SetWriteDeadline(time.Now().Add(stallLimit))
	return g.w.Write(p)
}

// done clears the deadline: without a server write timeout nothing else
// resets it, and the next request on a kept-alive connection would inherit
// a clock it never asked for.
func (g *stallGuard) done() { _ = g.rc.SetWriteDeadline(time.Time{}) }

// secure reports whether the request arrived over TLS, so the session cookie
// can be marked Secure. Behind a reverse proxy the answer comes from
// X-Forwarded-Proto, but only when we were told to trust it.
func (s *Server) secure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if s.cfg.TrustProxyHeaders {
		if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
			return strings.EqualFold(strings.TrimSpace(strings.Split(v, ",")[0]), "https")
		}
	}
	return false
}

// setSessionCookie issues the session cookie. HttpOnly keeps it away from
// scripts, SameSite=Strict blocks cross-site use, and Secure is set whenever
// the request is known to be over TLS.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   s.secure(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// securityHeaders applies the response headers that matter for an app exposed
// to the internet. The CSP is strict: no inline scripts, no external origins.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if !strings.HasPrefix(r.URL.Path, "/api/fs/download") {
			h.Set("Cache-Control", "no-store")
		}
		h.Set("Content-Security-Policy", strings.Join([]string{
			"default-src 'self'",
			"script-src 'self'",
			"style-src 'self'",
			"img-src 'self' data: blob:",
			"connect-src 'self'",
			"font-src 'self'",
			"object-src 'none'",
			"base-uri 'none'",
			"form-action 'self'",
			"frame-ancestors 'none'",
		}, "; "))
		next.ServeHTTP(w, r)
	})
}

// withRecovery turns a panic into a 500 instead of killing the process and
// dropping every other user's connection.
func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logError("panic serving request", "path", r.URL.Path, "err", rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestLogger writes one line per request.
func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Skip routine static asset hits; always log problems.
		if rec.status >= 400 || !strings.HasPrefix(r.URL.Path, "/static/") {
			s.logf("request",
				"ip", s.clientIP(r),
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"dur", time.Since(start).Round(time.Millisecond).String(),
			)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.written {
		s.status = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(b)
}

// Flush and Unwrap let http.ResponseController reach the underlying writer so
// streaming downloads are not buffered by this wrapper.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// ReadFrom keeps downloads zero-copy. http.ServeContent copies a file into
// the response with io.CopyN, which uses the writer's ReadFrom when it has
// one; net/http's own writer answers that with sendfile(2), so file bytes
// go from the page cache to the socket without passing through the process.
// Without this method the wrapper hid that path, and every download took a
// 32 KiB userspace copy loop instead: on a 2 GiB loopback download, about
// twice the CPU. Over TLS terminated here the bytes must be encrypted in
// the process anyway, and net/http falls back to copying by itself.
func (s *statusRecorder) ReadFrom(r io.Reader) (int64, error) {
	s.written = true
	if rf, ok := s.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(s.ResponseWriter, r)
}

// clientIP returns the peer address. X-Forwarded-For is deliberately ignored
// for rate limiting, since it is attacker-controlled unless a proxy overwrites
// it; trusting it would let anyone bypass the login limiter.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientIP returns the address a request is attributed to: the peer address
// on a direct connection, or the originator named by X-Forwarded-For when the
// request arrives through a proxy we were configured to trust. The header is
// only read when trust_proxy_headers is set, and only its first entry is
// used, which is safe only when the proxy replaces rather than appends (the
// sample Caddyfile does).
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			first := strings.TrimSpace(strings.Split(v, ",")[0])
			if first != "" {
				return first
			}
		}
	}
	return clientIP(r)
}

// originGuard rejects state-changing requests whose browser-announced origin
// does not match the host the request arrived for.
//
// SameSite=Strict already keeps the session cookie from riding along on
// cross-site requests, so this is defence in depth rather than the primary
// control: it also covers cases where the cookie constraint is bypassed by
// cookie-fixing or non-standard cookie handling. Requests without the
// headers (curl, and other non-browser clients) pass through untouched, and
// read methods are never blocked since they carry no side effects.
func originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			origin := r.Header.Get("Origin")
			if origin != "" && !originMatchesHost(origin, r.Host) {
				writeError(w, http.StatusForbidden, "cross-origin requests are not accepted")
				return
			}
			sf := r.Header.Get("Sec-Fetch-Site")
			if sf != "" && sf != "same-origin" && sf != "none" {
				writeError(w, http.StatusForbidden, "cross-origin requests are not accepted")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// originMatchesHost compares the origin's host:port with the request's Host
// header. Scheme is deliberately ignored: with TLS terminated anywhere
// (directly or at a proxy), what matters is the identity of the site, not
// how the client reached it.
func originMatchesHost(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// writeJSON sends a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	//nolint:errcheck // client disconnects are expected during downloads
	_ = json.NewEncoder(w).Encode(v)
}

// writeError sends a JSON error body. Messages are safe to display: internal
// failures are logged rather than returned, so paths and stack traces stay
// server-side.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "status": status})
}

// decodeJSON reads a JSON body with a size limit.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	return dec.Decode(dst)
}

// rateLimiter is a per-IP sliding-window limiter used to slow password
// guessing. It is in-memory by design: a restart clearing the counters is an
// acceptable trade for avoiding a dependency.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
	// lastPrune is when idle keys were last swept out of hits.
	lastPrune time.Time
	now       func() time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: make(map[string][]time.Time), now: time.Now}
}

// allow reports whether an attempt under key is within budget, and records
// it. Keys are client addresses (see rateKey) or other namespaced strings.
func (rl *rateLimiter) allow(key string) bool {
	now := rl.now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Once per window, drop every key with nothing left inside it. Pruning
	// only when an attempt was refused, as before, let a stream of fresh
	// addresses that never hit the limit grow the map without end.
	if now.Sub(rl.lastPrune) >= rl.window {
		for k, ts := range rl.hits {
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(rl.hits, k)
			}
		}
		rl.lastPrune = now
	}

	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	rl.hits[key] = kept

	if len(kept) >= rl.limit {
		return false
	}
	rl.hits[key] = append(kept, now)
	return true
}

// reset clears a key's counter. Called after a successful login so a
// legitimate user is not punished for earlier typos.
func (rl *rateLimiter) reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.hits, key)
}

// rateKey is the limiter key for a client address. IPv6 addresses are
// grouped by their /64: one subscriber is routinely handed a whole /64, so
// limiting single addresses would give an attacker 2^64 fresh budgets. IPv4
// (including IPv4-mapped IPv6) is limited per address. Anything that does
// not parse, such as an odd X-Forwarded-For value, is used as it stands.
func rateKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
