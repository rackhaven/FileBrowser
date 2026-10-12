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
	"sync"
	"time"
)

// Session is a logged-in browser/device. Sessions live server side rather than
// inside a signed cookie so that logout, password reset and "disable this
// account" all take effect immediately instead of waiting for a cookie to
// expire.
type Session struct {
	Token     string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Sessions is an in-memory session table with lazy expiry.
type Sessions struct {
	mu      sync.Mutex
	ttl     time.Duration
	byToken map[string]*Session
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

// Start issues a session token for a user. The token is 256 bits of random.
func (s *Sessions) Start(userID string) (*Session, error) {
	tok, err := RandomToken(32)
	if err != nil {
		return nil, err
	}
	now := s.now()
	sess := &Session{Token: tok, UserID: userID, CreatedAt: now, ExpiresAt: now.Add(s.ttl)}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	s.byToken[tok] = sess
	return sess, nil
}

// Lookup resolves a token to a live session, or nil if it is unknown or
// expired.
func (s *Sessions) Lookup(tok string) *Session {
	if tok == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	sess, ok := s.byToken[tok]
	if !ok || now.After(sess.ExpiresAt) {
		delete(s.byToken, tok)
		return nil
	}
	c := *sess
	return &c
}

// End revokes a single session.
func (s *Sessions) End(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byToken, tok)
}

// EndAllForUser revokes every session belonging to a user. Used on password
// change, admin reset and account deletion.
func (s *Sessions) EndAllForUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, sess := range s.byToken {
		if sess.UserID == userID {
			delete(s.byToken, tok)
		}
	}
}

// Touch extends the session's expiry, sliding the window for active users.
func (s *Sessions) Touch(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byToken[tok]; ok {
		sess.ExpiresAt = s.now().Add(s.ttl)
	}
}

// sweepLocked drops expired sessions. Callers must hold s.mu.
func (s *Sessions) sweepLocked(now time.Time) {
	for tok, sess := range s.byToken {
		if now.After(sess.ExpiresAt) {
			delete(s.byToken, tok)
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
