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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Session is a logged-in browser/device. Sessions live server side rather than
// inside a signed cookie so that logout, password reset and "disable this
// account" all take effect immediately instead of waiting for a cookie to
// expire.
//
// A session started by this process carries its raw token; a session reloaded
// from the durable table does not (only its SHA-256 is on disk), which is
// exactly sufficient: lookups key on the token hash, the browser still holds
// the raw value in its cookie, and only the short hint travels elsewhere.
type Session struct {
	Token     string
	PublicID  string
	Hint      string
	UserID    string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

// tokenHint is the short recognisable fragment of a session token shown to
// its owner. Six characters are enough to tell two sessions apart on one
// account and are far from enough to impersonate anyone.
func tokenHint(tok string) string {
	const hintChars = 6
	if len(tok) <= hintChars {
		return tok
	}
	return tok[:hintChars] + "..."
}

// sessionTokenHash reduces a token to its map key. The hash never needs to be
// reversible: to authenticate, the cookie's value is hashed the same way.
func sessionTokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// Sessions is a session table with lazy expiry, optionally persisted to a
// file so logged-in devices survive a restart.
type Sessions struct {
	mu      sync.Mutex
	ttl     time.Duration
	byToken map[string]*Session // keyed by sessionTokenHash, never the raw token
	path    string              // "" means memory only
	now     func() time.Time
}

func NewSessions(ttl time.Duration) *Sessions {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Sessions{
		ttl:     ttl,
		byToken: make(map[string]*Session),
		now:     time.Now,
	}
}

// sessionRecord is the durable form of one session. It deliberately holds the
// token's hash and not the token: whoever can read this file cannot therefore
// reuse a cookie from it, only recognise one.
type sessionRecord struct {
	TokenHash string    `json:"token_hash"`
	UserID    string    `json:"user_id"`
	PublicID  string    `json:"public_id"`
	Hint      string    `json:"hint"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OpenSessions is NewSessions with durability: the table loads from path and
// every change is written back before the mutation returns. A missing file is
// a fresh install and is not an error; a file that exists but cannot be read
// or parsed is, because quietly losing every session is harder to diagnose
// than a startup failure.
//
// Only Start stamps a raw token: reloaded sessions carry an empty Token. That
// is exactly sufficient, because lookups key on the token hash the browser's
// cookie value produces anyway, and a reloaded session resumes with the expiry
// it was saved with, which can only make a device sign out earlier than the
// sliding window would ask, never later.
func OpenSessions(path string, ttl time.Duration) (*Sessions, error) {
	s := NewSessions(ttl)
	s.path = path
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("auth: create data dir: %w", err)
	}

	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}

	var loaded []sessionRecord
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	now := s.now()
	for _, rec := range loaded {
		if rec.TokenHash == "" || rec.UserID == "" {
			continue // partial record
		}
		if now.After(rec.ExpiresAt) {
			continue // already dead; loaded tables are pruned
		}
		s.byToken[rec.TokenHash] = &Session{
			PublicID:  rec.PublicID,
			Hint:      rec.Hint,
			UserID:    rec.UserID,
			CreatedAt: rec.CreatedAt,
			LastSeen:  rec.LastSeen,
			ExpiresAt: rec.ExpiresAt,
		}
	}
	return s, nil
}

// saveLocked writes the live part of the table atomically. Callers hold s.mu;
// a failure here is returned, never folded away, because an in-memory change
// the file does not reflect would resurrect a revoked session after a restart.
func (s *Sessions) saveLocked() error {
	if s.path == "" {
		return nil
	}
	now := s.now()
	records := make([]sessionRecord, 0, len(s.byToken))
	for _, sess := range s.byToken {
		if now.After(sess.ExpiresAt) {
			continue // expired rows do not earn their keep
		}
		records = append(records, sessionRecord{
			TokenHash: sessionTokenHash(sess.Token),
			UserID:    sess.UserID,
			PublicID:  sess.PublicID,
			Hint:      sess.Hint,
			CreatedAt: sess.CreatedAt,
			LastSeen:  sess.LastSeen,
			ExpiresAt: sess.ExpiresAt,
		})
	}
	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("auth: encode sessions: %w", err)
	}
	// 0600: the file holds token hashes and account ids, keep it owner-only.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("auth: write %s: %w", tmp, err)
	}
	if err := syncReplace(tmp, s.path); err != nil {
		return fmt.Errorf("auth: replace %s: %w", s.path, err)
	}
	return nil
}

// Start issues a session token for a user. The token is 256 bits of random.
// Alongside it the session gets a short public id, so its owner can manage it
// from the devices list without ever being handed the live token. The table
// is saved before Start returns: a caller that does not get an error is
// guaranteed the session is on disk.
func (s *Sessions) Start(userID string) (*Session, error) {
	tok, err := RandomToken(32)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepLocked(now)
	id, err := s.newPublicIDLocked()
	if err != nil {
		return nil, err
	}
	sess := &Session{
		Token:     tok,
		PublicID:  id,
		Hint:      tokenHint(tok),
		UserID:    userID,
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.byToken[sessionTokenHash(tok)] = sess
	if err := s.saveLocked(); err != nil {
		// Memory and disk would disagree; rather than a session that comes
		// back after a restart, the caller sees why the login cannot finish.
		delete(s.byToken, sessionTokenHash(tok))
		return nil, err
	}
	return sess, nil
}

// newPublicIDLocked draws a short random id no live session carries. Callers
// must hold s.mu.
func (s *Sessions) newPublicIDLocked() (string, error) {
	for range 8 {
		id, err := RandomToken(4)
		if err != nil {
			return "", err
		}
		dup := false
		for _, sess := range s.byToken {
			if sess.PublicID == id {
				dup = true
				break
			}
		}
		if !dup {
			return id, nil
		}
	}
	return "", errors.New("auth: session ids keep colliding")
}

// Lookup resolves a token to a live session, or nil if it is unknown or
// expired.
func (s *Sessions) Lookup(tok string) *Session {
	hash := sessionTokenHash(tok)
	if tok == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	sess, ok := s.byToken[hash]
	if !ok || now.After(sess.ExpiresAt) {
		delete(s.byToken, hash)
		return nil
	}
	sess.LastSeen = now
	c := *sess
	return &c
}

// ListForUser returns live sessions for one user, newest first. The copies
// carry their public id and times but the caller is responsible for making
// sure the raw token never reaches a client.
func (s *Sessions) ListForUser(userID string) []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]Session, 0, 4)
	for _, sess := range s.byToken {
		if sess.UserID != userID || now.After(sess.ExpiresAt) {
			continue
		}
		out = append(out, *sess)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].CreatedAt.After(out[j-1].CreatedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Session errors for EndByID: one means the id names nothing the user owns,
// the other means the id would name several sessions at once, which must
// never happen and is refused rather than guessed at.
var (
	ErrNoSuchSession      = errors.New("auth: no such session")
	ErrSessionIDAmbiguous = errors.New("auth: session id matches several sessions")
)

// EndByID revokes the caller's session with the given public id, refusing on
// ambiguity and reporting a persistence failure rather than leaving a revoked
// session in the file to come back after a restart.
func (s *Sessions) EndByID(userID, publicID string) error {
	if publicID == "" {
		return ErrNoSuchSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var found string
	var sess *Session
	for hash, entry := range s.byToken {
		if entry.UserID == userID && entry.PublicID == publicID {
			if sess != nil {
				return ErrSessionIDAmbiguous
			}
			found = hash
			sess = entry
		}
	}
	if sess == nil {
		return ErrNoSuchSession
	}
	delete(s.byToken, found)
	if err := s.saveLocked(); err != nil {
		s.byToken[found] = sess // put it back: memory must match the file
		return err
	}
	return nil
}

// End revokes a single session. A persistence failure is returned and the
// session is put back, so memory never contains what the file has forgotten.
func (s *Sessions) End(tok string) error {
	hash := sessionTokenHash(tok)
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.byToken[hash]
	if !ok {
		return nil
	}
	delete(s.byToken, hash)
	if err := s.saveLocked(); err != nil {
		s.byToken[hash] = sess
		return err
	}
	return nil
}

// EndAllForUser revokes every session belonging to a user. Used on password
// change, admin reset and account deletion. On save failure nothing is
// revoked: the mutation waits for the disk.
func (s *Sessions) EndAllForUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var taken map[string]*Session
	for hash, sess := range s.byToken {
		if sess.UserID == userID {
			if taken == nil {
				taken = make(map[string]*Session)
			}
			taken[hash] = sess
			delete(s.byToken, hash)
		}
	}
	if taken == nil {
		return nil
	}
	if err := s.saveLocked(); err != nil {
		for hash, sess := range taken {
			s.byToken[hash] = sess
		}
		return err
	}
	return nil
}

// Touch extends the session's expiry, sliding the window for active users.
// The change stays in memory: expiry can only be shortened by a reload
// (a session resumes with its saved expiry), never stretched, so skipping
// the write keeps the per-request cost at zero without reopening a window.
func (s *Sessions) Touch(tok string) {
	hash := sessionTokenHash(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byToken[hash]; ok {
		sess.ExpiresAt = s.now().Add(s.ttl)
	}
}

// sweepLocked drops expired sessions. Callers must hold s.mu.
func (s *Sessions) sweepLocked(now time.Time) {
	for hash, sess := range s.byToken {
		if now.After(sess.ExpiresAt) {
			delete(s.byToken, hash)
		}
	}
}

// Count reports the number of live sessions (used by /api/status).
func (s *Sessions) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	return len(s.byToken)
}
