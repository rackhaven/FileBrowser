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
	"net/http"
	"strings"
	"time"

	"github.com/rackhaven/filebrowser/internal/auth"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type meResponse struct {
	User         auth.PublicUser `json:"user"`
	MustChange   bool            `json:"must_change_password"`
	SessionUntil string          `json:"session_expires"`
	Version      string          `json:"version"`
	Uptime       string          `json:"uptime"`
}

// uptime is how long the process has been up, rounded for stable output.
func (s *Server) uptime() string {
	return time.Since(s.started).Round(time.Second).String()
}

// handleLogin exchanges credentials for a session cookie.
//
// Failures are deliberately indistinguishable: an unknown user and a wrong
// password both take the same time and return the same message, so the
// endpoint cannot be used to enumerate accounts.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.limiter.allow(ip) {
		w.Header().Set("Retry-After", "900")
		writeError(w, http.StatusTooManyRequests, "too many sign-in attempts, try again later")
		return
	}

	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !s.allowLogin(w) {
		return
	}
	defer func() { <-s.loginGate }()
	req.Username = strings.TrimSpace(req.Username)

	user, err := s.users.GetByUsername(req.Username)
	if err != nil {
		// Hash anyway so timing does not reveal whether the user exists.
		_, _ = auth.HashPassword(req.Password)
		writeError(w, http.StatusUnauthorized, "incorrect username or password")
		return
	}

	ok, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		s.logError("password hash problem", "user", user.Username, "err", err)
		writeError(w, http.StatusUnauthorized, "incorrect username or password")
		return
	}
	if !ok || user.Disabled {
		writeError(w, http.StatusUnauthorized, "incorrect username or password")
		return
	}

	sess, err := s.sessions.Start(user.ID)
	if err != nil {
		s.logError("could not start session", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start session")
		return
	}
	s.limiter.reset(ip) // don't penalise a user who fumbled the password earlier
	s.setSessionCookie(w, r, sess.Token, sess.ExpiresAt)

	s.logf("login", "user", user.Username, "ip", ip)
	writeJSON(w, http.StatusOK, meResponse{
		User:       user.Public(),
		MustChange: user.MustChangePassword,
		Version:    s.version,
		Uptime:     s.uptime(),
	})
}

// handleLogout revokes the server-side session, so the token is dead even if
// it was copied out of the browser.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		s.sessions.End(c.Value)
	}
	s.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleMe returns the current identity, used by the PWA on startup to decide
// whether to show the login screen or the file list.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	writeJSON(w, http.StatusOK, meResponse{
		User:       u.Public(),
		MustChange: u.MustChangePassword,
		Version:    s.version,
		Uptime:     s.uptime(),
	})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// handleChangePassword lets a user rotate their own password. Every other
// session for that account is revoked, so a stolen cookie dies with the change.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())

	var req changePasswordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ok, err := auth.VerifyPassword(req.CurrentPassword, u.PasswordHash)
	if err != nil || !ok {
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	if !auth.ValidPassword(req.NewPassword) {
		writeError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	if req.CurrentPassword == req.NewPassword {
		writeError(w, http.StatusBadRequest, "new password must differ from the current one")
		return
	}

	if err := s.users.SetPassword(u.ID, req.NewPassword, false); err != nil {
		s.logError("could not change password", "user", u.Username, "err", err)
		writeError(w, http.StatusInternalServerError, "could not change password")
		return
	}

	// Keep this device signed in, drop every other one.
	s.sessions.EndAllForUser(u.ID)
	if newSess, err := s.sessions.Start(u.ID); err == nil {
		s.setSessionCookie(w, r, newSess.Token, newSess.ExpiresAt)
	}

	s.logf("password changed", "user", u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleStatus reports whether any account exists yet. It is unauthenticated
// on purpose so a fresh install can show a "create the first admin" prompt,
// and deliberately says nothing else: version and uptime would help someone
// fingerprint the install, so they arrive only with an authenticated
// /api/auth/me response instead.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"needs_bootstrap": s.users.Count() == 0,
	})
}
