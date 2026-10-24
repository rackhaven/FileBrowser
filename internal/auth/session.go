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
	"errors"
	"sync"
	"time"
)

// Session is a logged-in browser/device. Sessions live server side rather than
// inside a signed cookie so that logout, password reset and "disable this
// account" all take effect immediately instead of waiting for a cookie to
// expire.
type Session struct {
	Token     string
	PublicID  string
	UserID    string
	CreatedAt time.Time
	LastSeen  time.Time
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
// Alongside it the session gets a short public id, so its owner can manage it
// from the devices list without ever being handed the live token.
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
		UserID:    userID,
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.byToken[tok] = sess
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
// ambiguity. It reports which refusal through the returned error.
func (s *Sessions) EndByID(userID, publicID string) error {
	if publicID == "" {
		return ErrNoSuchSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var tokens []string
	for tok, sess := range s.byToken {
		if sess.UserID == userID && sess.PublicID == publicID {
			tokens = append(tokens, tok)
		}
	}
	switch {
	case len(tokens) == 0:
		return ErrNoSuchSession
	case len(tokens) > 1:
		return ErrSessionIDAmbiguous
	}
	delete(s.byToken, tokens[0])
	return nil
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
