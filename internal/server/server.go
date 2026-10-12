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
	stdfs "io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lennox/filebrowser/internal/auth"
	"github.com/lennox/filebrowser/internal/fs"
)

type ctxKey string

const (
	ctxUser  ctxKey = "user"
	ctxToken ctxKey = "token"
)

const sessionCookie = "fb_session"

// Config is the subset of configuration the HTTP layer needs.
type Config struct {
	TrustProxyHeaders bool
	SessionTTL        time.Duration
}

// Server wires the user store, sessions, filesystem view and HTTP routes.
type Server struct {
	cfg      Config
	users    *auth.Store
	sessions *auth.Sessions
	files    *fs.FS
	static   stdfs.FS
	limiter  *rateLimiter
	started  time.Time
	version  string
	log      *slog.Logger
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
	return &Server{
		cfg:      opt.Config,
		users:    opt.Users,
		sessions: sessions,
		files:    opt.FS,
		static:   opt.Static,
		limiter:  newRateLimiter(8, 15*time.Minute),
		started:  time.Now(),
		version:  opt.Version,
		log:      logger,
	}
}

func (s *Server) logf(msg string, args ...any) {
	s.log.Info(msg, args...)
}

func (s *Server) logError(msg string, args ...any) {
	s.log.Error(msg, args...)
}

// requireAuth wraps a handler so it only runs for a logged-in user.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, err := r.Cookie(sessionCookie)
		if err != nil || tok.Value == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		sess := s.sessions.Lookup(tok.Value)
		if sess == nil {
			s.clearSessionCookie(w, r) // stop the browser resending a dead token
			writeError(w, http.StatusUnauthorized, "session expired, please sign in again")
			return
		}

		user, err := s.users.Get(sess.UserID)
		if err != nil || user.Disabled {
			// Account deleted or disabled while this session was live.
			s.sessions.End(sess.Token)
			s.clearSessionCookie(w, r)
			writeError(w, http.StatusUnauthorized, "account is no longer active")
			return
		}

		s.sessions.Touch(sess.Token) // sliding expiry for active users
		ctx := context.WithValue(r.Context(), ctxUser, user)
		ctx = context.WithValue(ctx, ctxToken, sess.Token)
		next(w, r.WithContext(ctx))
	}
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
				"ip", clientIP(r),
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
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: make(map[string][]time.Time)}
}

// allow reports whether an attempt from ip is within budget, and records it.
func (rl *rateLimiter) allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	kept := rl.hits[ip][:0]
	for _, t := range rl.hits[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	rl.hits[ip] = kept

	if len(kept) >= rl.limit {
		// Opportunistically evict idle IPs so the map cannot grow forever.
		if len(rl.hits) > 4096 {
			for k, ts := range rl.hits {
				if len(ts) == 0 || ts[len(ts)-1].Before(cutoff) {
					delete(rl.hits, k)
				}
			}
		}
		return false
	}
	rl.hits[ip] = append(kept, now)
	return true
}

// reset clears an IP's counter. Called after a successful login so a legitimate
// user is not punished for earlier typos.
func (rl *rateLimiter) reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.hits, ip)
}
