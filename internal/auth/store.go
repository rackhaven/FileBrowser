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
//
// Two processes may hold the same database open: the server and the CLI
// (`filebrowser user ...`). They coordinate through an advisory lock on
// users.json.lock, and every mutation first re-reads the file when it changed
// underneath us, so a CLI password reset cannot be silently overwritten by
// the server's next save. Reads refresh the same way, so an account the CLI
// removes or resets stops working on a running server at its next request.
// The lock file is separate because users.json itself is replaced on every
// write, which would strand a lock on a dead inode.
type Store struct {
	mu   sync.RWMutex
	path string
	// lockFile is held open for the life of the process; the advisory lock
	// taken on it lives with the open file description, so a crashed process
	// never strands the lock.
	lockFile *os.File
	// last describes the copy of the database this process last read or
	// wrote, for change detection; nil when there was no file.
	last os.FileInfo
	db   database
}

const dbVersion = 1

// OpenStore loads (or creates) the user database at path.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, db: database{Version: dbVersion}}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("auth: create data dir: %w", err)
	}

	// The lock file is opened here rather than next to the data file because
	// users.json is replaced by rename on every save; a lock on it would die
	// with each write. Creation happens for fresh installs too, since every
	// write path depends on the lock existing.
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("auth: open %s.lock: %w", path, err)
	}
	s.lockFile = lock

	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.noteStat()
		return s, nil // fresh install; no users yet
	case err != nil:
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}

	if err := json.Unmarshal(raw, &s.db); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	for _, u := range s.db.Users {
		u.Username = strings.ToLower(strings.TrimSpace(u.Username))
		u.Grants = normaliseGrants(u.Grants)
	}

	s.noteStat()
	return s, nil
}

// noteStat remembers the size and modtime of the database file as last seen.
// Callers invoke it right after loading or right after a successful save, so
// a change made by anyone else registers as new.
//
// The stat and the recording happen under the store mutex. Stating first and
// locking second would leave a window where another goroutine's save lands
// in between and the recorded stamp describes a file we never read.
func (s *Store) noteStat() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noteStatLocked()
}

// noteStatLocked is noteStat for callers already holding the mutex.
func (s *Store) noteStatLocked() {
	info, err := os.Stat(s.path)
	if err != nil {
		s.last = nil
		return
	}
	s.last = info
}

// unchangedLocked reports whether info describes the copy last seen. Every
// save replaces the file by rename, so a new file is a new inode: SameFile
// catches a rewrite even when size and mtime match, as two password hashes
// of equal length written within one coarse mtime tick would.
func (s *Store) unchangedLocked(info os.FileInfo) bool {
	return s.last != nil && os.SameFile(info, s.last) &&
		info.Size() == s.last.Size() && info.ModTime().Equal(s.last.ModTime())
}

// reloadIfChanged replaces the in-memory database when another process wrote
// the file since we last read or wrote it. The caller must hold the
// cross-process lock, which closes the window between read and save.
//
// The read and the replacement happen under the store mutex. They must be
// one critical section: flock serialises them only across processes (it is
// per file description, so it never blocks another goroutine of this same
// process), and an unlocked replace would wipe a commit that another
// goroutine of this process had just saved between our read and our swap.
func (s *Store) reloadIfChanged() error {
	info, err := os.Stat(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Never seen (install still fresh), or transient. Keep what we have.
		return nil
	case err != nil:
		return fmt.Errorf("auth: stat %s: %w", s.path, err)
	}
	s.mu.RLock()
	unchanged := s.unchangedLocked(info)
	s.mu.RUnlock()
	if unchanged {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check: the file may have changed again while we waited.
	if s.unchangedLocked(info) {
		return nil
	}
	raw, rerr := os.ReadFile(s.path)
	if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return fmt.Errorf("auth: read %s: %w", s.path, rerr)
	}
	if rerr == nil {
		fresh := database{Version: dbVersion}
		if jerr := json.Unmarshal(raw, &fresh); jerr != nil {
			return fmt.Errorf("auth: parse %s: %w", s.path, jerr)
		}
		for _, u := range fresh.Users {
			u.Username = strings.ToLower(strings.TrimSpace(u.Username))
			u.Grants = normaliseGrants(u.Grants)
		}
		s.db.Users = fresh.Users
	}
	// Stamp what is on disk now. If the file moved on between the read and
	// this stat, the next accessor sees the difference and reloads once
	// more; convergence, not loss.
	s.noteStatLocked()
	return nil
}

// withFileLock runs op under the cross-process lock, after first pulling in
// any changes another process has written. Everything that modifies the
// database goes through here, which is what makes a CLI edit safe to run
// against a live server: the stale copy is refreshed, not saved over.
func (s *Store) withFileLock(op func() error) error {
	if err := s.lockEx(); err != nil {
		return fmt.Errorf("auth: lock %s: %w", s.path, err)
	}
	defer func() {
		_ = s.lockUn() // distinctly unlikely to fail; a released process exits
	}()

	if err := s.reloadIfChanged(); err != nil {
		return err
	}
	if err := op(); err != nil {
		return err
	}
	s.noteStat()
	return nil
}

// refresh pulls in another process's writes before a read. It takes no
// cross-process lock: saves land by atomic rename, so the file is always
// one complete version or the next. A file that cannot be read or parsed
// leaves the last good copy in service rather than locking everyone out;
// the next mutation, which does report errors, will surface it.
func (s *Store) refresh() {
	_ = s.reloadIfChanged()
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
	if err := syncReplace(tmp, s.path); err != nil {
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
	s.refresh()
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
	s.refresh()
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
	s.refresh()
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
	s.refresh()
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

	created := &User{
		ID:           id,
		Username:     username,
		PasswordHash: hash,
		Admin:        admin,
		Grants:       normaliseGrants(grants),
		CreatedAt:    time.Now().UTC(),
	}
	err = s.withFileLock(func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, u := range s.db.Users {
			if u.Username == username {
				return ErrUserExists
			}
		}
		s.db.Users = append(s.db.Users, created)
		if err := s.save(); err != nil {
			s.db.Users = s.db.Users[:len(s.db.Users)-1]
			return err
		}
		return nil
	})
	if err != nil {
		return PublicUser{}, err
	}
	return created.Public(), nil
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

	return s.withFileLock(func() error {
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
	})
}

// Update changes the non-secret attributes of an account.
func (s *Store) Update(id string, mutate func(*User)) (PublicUser, error) {
	var updated PublicUser
	err := s.withFileLock(func() error {
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
				return ErrLastAdmin
			}

			if err := s.save(); err != nil {
				*u = snapshot
				return err
			}
			updated = u.Public()
			return nil
		}
		return ErrNotFound
	})
	if err != nil {
		return PublicUser{}, err
	}
	return updated, nil
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
	return s.withFileLock(func() error {
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
	})
}

// normaliseGrants canonicalises paths and drops empty or zero-level rules so
// comparisons later on are apples to apples. A legacy "admin" grant becomes
// write: it never granted more, and admin is no longer a grant level.
func normaliseGrants(in []Grant) []Grant {
	out := make([]Grant, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, g := range in {
		if g.Level > AccessWrite {
			g.Level = AccessWrite
		}
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
