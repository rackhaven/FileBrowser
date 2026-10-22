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
	"errors"
	"net/http"
	"strings"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// handleListUsers returns all accounts (admin only).
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users := s.users.List()
	out := make([]auth.PublicUser, 0, len(users))
	for _, u := range users {
		out = append(out, u.Public())
	}
	writeJSON(w, http.StatusOK, out)
}

type createUserRequest struct {
	Username string       `json:"username"`
	Password string       `json:"password"`
	Admin    bool         `json:"admin"`
	Grants   []auth.Grant `json:"grants"`
}

// handleCreateUser adds an account (admin only).
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	grants, err := validateGrants(req.Grants)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	pub, err := s.users.Create(req.Username, req.Password, req.Admin, grants)
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}

	actor := userFrom(r.Context())
	s.logf("user created", "actor", actor.Username, "user", pub.Username, "admin", pub.Admin)
	writeJSON(w, http.StatusCreated, pub)
}

type updateUserRequest struct {
	Admin    *bool         `json:"admin"`
	Disabled *bool         `json:"disabled"`
	Grants   *[]auth.Grant `json:"grants"`
}

// handleUpdateUser edits an account (admin only).
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req updateUserRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var grants []auth.Grant
	if req.Grants != nil {
		var err error
		grants, err = validateGrants(*req.Grants)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	pub, err := s.users.Update(id, func(u *auth.User) {
		if req.Admin != nil {
			u.Admin = *req.Admin
		}
		if req.Disabled != nil {
			u.Disabled = *req.Disabled
		}
		if req.Grants != nil {
			u.Grants = grants
		}
	})
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}

	// Disabling an account must take effect now, not when its cookie expires.
	if req.Disabled != nil && *req.Disabled {
		s.sessions.EndAllForUser(id)
	}

	actor := userFrom(r.Context())
	s.logf("user updated", "actor", actor.Username, "user", pub.Username)
	writeJSON(w, http.StatusOK, pub)
}

type resetPasswordRequest struct {
	Password string `json:"password"`
}

// handleResetPassword sets a user's password from the admin panel and forces
// them to change it at next login.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req resetPasswordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.users.SetPassword(id, req.Password, true); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	s.sessions.EndAllForUser(id)

	actor := userFrom(r.Context())
	if u, err := s.users.Get(id); err == nil {
		s.logf("password reset", "actor", actor.Username, "user", u.Username)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleDeleteUser removes an account (admin only).
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.users.Delete(id); err != nil {
		s.writeUserError(w, r, err)
		return
	}
	s.sessions.EndAllForUser(id)

	actor := userFrom(r.Context())
	s.logf("user deleted", "actor", actor.Username, "id", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleBootstrap creates the very first account on an empty instance. There is
// no authentication, so it is only accepted while zero users exist, which is
// the window between starting a fresh container and locking it down.
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if s.users.Count() > 0 {
		writeError(w, http.StatusForbidden, "this instance is already set up; sign in as an administrator instead")
		return
	}

	var req createUserRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Admin = true // the first account is always an administrator

	pub, err := s.users.Create(req.Username, req.Password, true, nil)
	if err != nil {
		s.writeUserError(w, r, err)
		return
	}
	s.logf("bootstrap admin created", "user", pub.Username, "ip", s.clientIP(r))
	writeJSON(w, http.StatusCreated, pub)
}

// writeUserError maps store errors to HTTP responses.
func (s *Server) writeUserError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "user not found")
	case errors.Is(err, auth.ErrUserExists):
		writeError(w, http.StatusConflict, "that username is already taken")
	case errors.Is(err, auth.ErrBadUsername):
		writeError(w, http.StatusBadRequest, "username may use letters, digits, dot, dash and underscore")
	case errors.Is(err, auth.ErrBadPassword):
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
	case errors.Is(err, auth.ErrLastAdmin):
		writeError(w, http.StatusConflict, "this is the last administrator; promote another user first")
	default:
		s.logError("user store error", "err", err)
		writeError(w, http.StatusInternalServerError, "could not complete the request")
	}
}

// validateGrants normalises and sanity-checks access rules. Traversal segments
// are rejected outright rather than silently cleaned, so an admin who types a
// typo is told about it instead of quietly getting a different rule. Note that
// grant paths are virtual: "/etc" means <root>/etc, never the real /etc.
func validateGrants(in []auth.Grant) ([]auth.Grant, error) {
	out := make([]auth.Grant, 0, len(in))
	for _, g := range in {
		p := strings.ReplaceAll(strings.TrimSpace(g.Path), "\\", "/")
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			return nil, errors.New("grant paths must start with /")
		}
		if strings.ContainsRune(p, 0) {
			return nil, errors.New("grant paths must not contain null bytes")
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				return nil, errors.New("grant paths must not contain ..")
			}
		}
		if g.Level == auth.AccessNone {
			continue
		}
		out = append(out, auth.Grant{Path: cleanGrantPath(p), Level: g.Level})
	}
	return out, nil
}

// cleanGrantPath collapses empty and "." segments and any trailing slash.
func cleanGrantPath(p string) string {
	parts := strings.Split(p, "/")
	kept := make([]string, 0, len(parts))
	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}
		kept = append(kept, seg)
	}
	if len(kept) == 0 {
		return "/"
	}
	return "/" + strings.Join(kept, "/")
}
