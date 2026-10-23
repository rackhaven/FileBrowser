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
	"io/fs"
	"net/http"
	"strings"
)

// Handler builds the fully wrapped http.Handler for the service.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// ---- public ----------------------------------------------------------
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/bootstrap", s.handleBootstrap)
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// ---- authenticated ---------------------------------------------------
	mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("POST /api/auth/password", s.requireAuth(s.handleChangePassword))

	mux.HandleFunc("GET /api/fs/list", s.requireAuth(s.handleList))
	mux.HandleFunc("GET /api/fs/info", s.requireAuth(s.handleInfo))
	mux.HandleFunc("GET /api/fs/search", s.requireAuth(s.handleSearch))
	mux.HandleFunc("GET /api/fs/download", s.requireAuth(s.handleDownload))
	mux.HandleFunc("HEAD /api/fs/download", s.requireAuth(s.handleDownload))
	mux.HandleFunc("GET /api/fs/zip", s.requireAuth(s.handleZip))
	mux.HandleFunc("GET /api/fs/usage", s.requireAuth(s.handleUsage))
	mux.HandleFunc("PUT /api/fs/upload", s.requireAuth(s.handleUpload))
	mux.HandleFunc("POST /api/fs/mkdir", s.requireAuth(s.handleMkdir))
	mux.HandleFunc("POST /api/fs/delete", s.requireAuth(s.handleDelete))
	mux.HandleFunc("POST /api/fs/rename", s.requireAuth(s.handleRename))

	// ---- admin -----------------------------------------------------------
	mux.HandleFunc("GET /api/admin/users", s.requireAdmin(s.handleListUsers))
	mux.HandleFunc("POST /api/admin/users", s.requireAdmin(s.handleCreateUser))
	mux.HandleFunc("PATCH /api/admin/users/{id}", s.requireAdmin(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/admin/users/{id}", s.requireAdmin(s.handleDeleteUser))
	mux.HandleFunc("POST /api/admin/users/{id}/password", s.requireAdmin(s.handleResetPassword))

	// ---- the PWA ---------------------------------------------------------
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.static)))
	mux.HandleFunc("GET /manifest.webmanifest", s.serveManifest)
	mux.HandleFunc("GET /sw.js", s.serveServiceWorker)

	// Catch-all. This must be the ONLY "/" pattern: an extra "GET /" entry
	// would be more specific and would serve the HTML shell for unknown API
	// routes, hiding 404s behind a 200. handleNotFound already returns the
	// shell for navigations and JSON for /api/.
	mux.HandleFunc("/", s.handleNotFound)

	return s.withRecovery(s.requestLogger(originGuard(securityHeaders(mux))))
}

// handleNotFound serves the SPA shell for unknown non-API paths, so deep links
// like /shared/photo work on reload, but returns JSON for API routes.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeError(w, http.StatusNotFound, "no such endpoint")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.serveIndex(w, r)
}

// serveIndex returns the PWA shell. It is deliberately unauthenticated: the
// app itself checks for a session and shows the login screen, so gating the
// shell would break the ability to sign in in the first place.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(s.static, "index.html")
	if err != nil {
		s.logError("missing embedded index.html", "err", err)
		writeError(w, http.StatusInternalServerError, "web interface unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The shell must never be cached, or a deploy leaves clients on old code.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	//nolint:errcheck // client disconnects are expected
	_, _ = w.Write(data)
}

// serveServiceWorker must be served from the root scope to control the whole
// origin, and must not be cached or browsers will never pick up updates.
func (s *Server) serveServiceWorker(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(s.static, "sw.js")
	if err != nil {
		writeError(w, http.StatusNotFound, "service worker unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Service-Worker-Allowed", "/")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck
	_, _ = w.Write(data)
}

// serveManifest returns the web app manifest.
func (s *Server) serveManifest(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(s.static, "manifest.webmanifest")
	if err != nil {
		writeError(w, http.StatusNotFound, "manifest unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck
	_, _ = w.Write(data)
}
