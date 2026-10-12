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

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Errors returned by the store.
var (
	ErrNotFound    = errors.New("auth: user not found")
	ErrUserExists  = errors.New("auth: user already exists")
	ErrBadUsername = errors.New("auth: username must be 1-64 chars of letters, digits, dot, dash or underscore")
	ErrBadPassword = errors.New("auth: password must be at least 8 characters")
	ErrLastAdmin   = errors.New("auth: refusing to remove the last enabled administrator")
)

type database struct {
	Version int     `json:"version"`
	Users   []*User `json:"users"`
}

// Store is a JSON-file-backed user database. Writes are serialised and land
// atomically via a temp file + rename, so a crash mid-write cannot corrupt the
// only copy of the accounts.
type Store struct {
	mu   sync.RWMutex
	path string
	db   database
}

const dbVersion = 1

// OpenStore loads (or creates) the user database at path.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, db: database{Version: dbVersion}}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("auth: create data dir: %w", err)
	}

	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil // fresh install; no users yet
	case err != nil:
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}

	if err := json.Unmarshal(raw, &s.db); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	for _, u := range s.db.Users {
		u.Username = strings.ToLower(strings.TrimSpace(u.Username))
	}
	return s, nil
}

// save writes the database atomically. Callers must hold s.mu.
func (s *Store) save() error {
	raw, err := json.MarshalIndent(s.db, "", "  ")
	if err != nil {
		return fmt.Errorf("auth: encode db: %w", err)
	}
	tmp := s.path + ".tmp"
	// 0600: the file contains password hashes, keep it owner-only.
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("auth: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("auth: replace %s: %w", s.path, err)
	}
	return nil
}

// ValidUsername reports whether name is acceptable.
func ValidUsername(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// ValidPassword reports whether a password meets the minimum length. We do not
// force character-class rules; length is what actually resists guessing.
func ValidPassword(p string) bool { return len(p) >= 8 }

// List returns every user, sorted by username.
func (s *Store) List() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*User, 0, len(s.db.Users))
	for _, u := range s.db.Users {
		c := *u
		c.Grants = append([]Grant(nil), u.Grants...)
		out = append(out, &c)
	}
	sortByUsername(out)
	return out
}

func sortByUsername(users []*User) {
	for i := 1; i < len(users); i++ {
		for j := i; j > 0 && users[j].Username < users[j-1].Username; j-- {
			users[j], users[j-1] = users[j-1], users[j]
		}
	}
}

// Get returns a user by ID.
func (s *Store) Get(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.db.Users {
		if u.ID == id {
			c := *u
			c.Grants = append([]Grant(nil), u.Grants...)
			return &c, nil
		}
	}
	return nil, ErrNotFound
}

// GetByUsername returns a user by their lowercased username.
func (s *Store) GetByUsername(name string) (*User, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.db.Users {
		if u.Username == name {
			c := *u
			c.Grants = append([]Grant(nil), u.Grants...)
			return &c, nil
		}
	}
	return nil, ErrNotFound
}

// Count reports the number of stored accounts.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.db.Users)
}

// Create adds a new account with an argon2id-hashed password.
func (s *Store) Create(username, password string, admin bool, grants []Grant) (PublicUser, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !ValidUsername(username) {
		return PublicUser{}, ErrBadUsername
	}
	if !ValidPassword(password) {
		return PublicUser{}, ErrBadPassword
	}
	hash, err := HashPassword(password)
	if err != nil {
		return PublicUser{}, err
	}
	id, err := randomID()
	if err != nil {
		return PublicUser{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.db.Users {
		if u.Username == username {
			return PublicUser{}, ErrUserExists
		}
	}
	u := &User{
		ID:           id,
		Username:     username,
		PasswordHash: hash,
		Admin:        admin,
		Grants:       normaliseGrants(grants),
		CreatedAt:    time.Now().UTC(),
	}
	s.db.Users = append(s.db.Users, u)
	if err := s.save(); err != nil {
		s.db.Users = s.db.Users[:len(s.db.Users)-1]
		return PublicUser{}, err
	}
	return u.Public(), nil
}

// SetPassword replaces a user's password. When force is true the user is
// required to change it at next login (used when an admin resets it).
func (s *Store) SetPassword(id, password string, force bool) error {
	if !ValidPassword(password) {
		return ErrBadPassword
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.db.Users {
		if u.ID != id {
			continue
		}
		oldHash, oldForce := u.PasswordHash, u.MustChangePassword
		u.PasswordHash = hash
		u.MustChangePassword = force
		if err := s.save(); err != nil {
			u.PasswordHash, u.MustChangePassword = oldHash, oldForce
			return err
		}
		return nil
	}
	return ErrNotFound
}

// Update changes the non-secret attributes of an account.
func (s *Store) Update(id string, mutate func(*User)) (PublicUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.db.Users {
		if u.ID != id {
			continue
		}
		snapshot := *u
		mutate(u)
		u.Grants = normaliseGrants(u.Grants)

		// Never let the last enabled admin be demoted or disabled, otherwise
		// the instance becomes unmanageable over the network.
		if (snapshot.Admin && !u.Admin || snapshot.Admin && u.Disabled) && s.enabledAdminCountLocked(u.ID) == 0 {
			u.Admin = snapshot.Admin
			u.Disabled = snapshot.Disabled
			return PublicUser{}, ErrLastAdmin
		}

		if err := s.save(); err != nil {
			*u = snapshot
			return PublicUser{}, err
		}
		return u.Public(), nil
	}
	return PublicUser{}, ErrNotFound
}

// enabledAdminCountLocked counts enabled admins, optionally excluding one ID.
func (s *Store) enabledAdminCountLocked(exclude string) int {
	n := 0
	for _, u := range s.db.Users {
		if u.Admin && !u.Disabled && u.ID != exclude {
			n++
		}
	}
	return n
}

// Delete removes an account.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.db.Users {
		if u.ID != id {
			continue
		}
		if u.Admin && !u.Disabled && s.enabledAdminCountLocked(u.ID) == 0 {
			return ErrLastAdmin
		}
		snapshot := append([]*User(nil), s.db.Users...)
		s.db.Users = append(s.db.Users[:i], s.db.Users[i+1:]...)
		if err := s.save(); err != nil {
			s.db.Users = snapshot
			return err
		}
		return nil
	}
	return ErrNotFound
}

// normaliseGrants canonicalises paths and drops empty or zero-level rules so
// comparisons later on are apples to apples.
func normaliseGrants(in []Grant) []Grant {
	out := make([]Grant, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, g := range in {
		p := normalizeVirtual(g.Path)
		if g.Level == AccessNone || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, Grant{Path: p, Level: g.Level})
	}
	return out
}

func randomID() (string, error) {
	tok, err := RandomToken(12)
	if err != nil {
		return "", err
	}
	return tok, nil
}
