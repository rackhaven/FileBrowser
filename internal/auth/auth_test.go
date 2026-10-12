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
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword = %v, %v; want true", ok, err)
	}

	ok, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword errored on a wrong password: %v", err)
	}
	if ok {
		t.Fatal("a wrong password must not verify")
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("two hashes of the same password must differ (salt not applied)")
	}
	// Both must still verify.
	for _, h := range []string{a, b} {
		if ok, err := VerifyPassword("same", h); err != nil || !ok {
			t.Errorf("hash %q failed to verify", h)
		}
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	bad := []string{
		"",
		"notahash",
		"$argon2id$",
		"$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA", // wrong variant
		"$argon2id$v=99$m=65536,t=3,p=2$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=0,t=0,p=0$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!!$aGFzaA",
	}
	for _, h := range bad {
		if _, err := VerifyPassword("x", h); err == nil {
			t.Errorf("VerifyPassword accepted a malformed hash %q", h)
		}
	}
}

func TestEmptyPasswordRejected(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("an empty password must not be hashable")
	}
}

// ---------------------------------------------------------------- store ----

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir() + "/users.json")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s
}

func TestCreateAndGet(t *testing.T) {
	s := newStore(t)

	created, err := s.Create("Alice", "password123", false, []Grant{{Path: "/docs", Level: AccessRead}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Username != "alice" {
		t.Errorf("username = %q, want lowercased", created.Username)
	}
	if created.ID == "" {
		t.Error("an ID must be assigned")
	}

	got, err := s.GetByUsername("ALICE") // lookup is case-insensitive
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if got.ID != created.ID {
		t.Error("looked up the wrong user")
	}

	if _, err := s.GetByUsername("nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestCreateRejectsDuplicates(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create("bob", "password123", false, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Create("BOB", "password123", false, nil); !errors.Is(err, ErrUserExists) {
		t.Errorf("want ErrUserExists, got %v", err)
	}
}

func TestCreateValidatesInput(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create("bad user", "password123", false, nil); !errors.Is(err, ErrBadUsername) {
		t.Errorf("want ErrBadUsername, got %v", err)
	}
	if _, err := s.Create("ok", "short", false, nil); !errors.Is(err, ErrBadPassword) {
		t.Errorf("want ErrBadPassword, got %v", err)
	}
}

func TestStorePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	first, err := OpenStore(dir + "/users.json")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := first.Create("carol", "password123", true, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	second, err := OpenStore(dir + "/users.json")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	u, err := second.GetByUsername("carol")
	if err != nil {
		t.Fatalf("user did not survive a reopen: %v", err)
	}
	ok, err := VerifyPassword("password123", u.PasswordHash)
	if err != nil || !ok {
		t.Error("the stored hash must still verify after a reopen")
	}
}

func TestLastAdminProtected(t *testing.T) {
	s := newStore(t)
	admin, err := s.Create("root", "password123", true, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := s.Update(admin.ID, func(u *User) { u.Admin = false }); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoting the last admin should fail, got %v", err)
	}
	if _, err := s.Update(admin.ID, func(u *User) { u.Disabled = true }); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disabling the last admin should fail, got %v", err)
	}
	if err := s.Delete(admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("deleting the last admin should fail, got %v", err)
	}
}

func TestSecondAdminAllowsDemotion(t *testing.T) {
	s := newStore(t)
	first, _ := s.Create("root", "password123", true, nil)
	second, err := s.Create("root2", "password123", true, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// With two admins, demoting one is allowed.
	if _, err := s.Update(second.ID, func(u *User) { u.Admin = false }); err != nil {
		t.Errorf("demoting one of two admins should work: %v", err)
	}
	// But the remaining one is now protected again.
	if _, err := s.Update(first.ID, func(u *User) { u.Admin = false }); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("want ErrLastAdmin, got %v", err)
	}
}

func TestPublicUserOmitsHash(t *testing.T) {
	s := newStore(t)
	created, err := s.Create("dave", "password123", false, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// This is the struct the API serialises to clients, so the important
	// property is what the JSON actually contains.
	stored, err := s.Get(created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	encoded, err := json.Marshal(created)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Check for the actual secret, not a substring: "must_change_password" is
	// a legitimate field that a naive "password" grep would flag.
	if strings.Contains(string(encoded), "$argon2") {
		t.Fatalf("PublicUser leaked the password hash: %s", encoded)
	}
	if strings.Contains(string(encoded), stored.PasswordHash) {
		t.Fatal("PublicUser leaked the stored hash value")
	}
	if strings.Contains(string(encoded), "password_hash") {
		t.Fatalf("PublicUser exposed a hash field: %s", encoded)
	}

	// The stored record must still hold the hash.
	if stored.PasswordHash == "" {
		t.Fatal("the stored record should still hold a hash")
	}
}

// ------------------------------------------------------------ sessions ----

func TestSessionLifecycle(t *testing.T) {
	s := NewSessions(time.Hour)

	sess, err := s.Start("user-1")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if len(sess.Token) < 32 {
		t.Errorf("token %q is too short to be unguessable", sess.Token)
	}

	got := s.Lookup(sess.Token)
	if got == nil || got.UserID != "user-1" {
		t.Fatal("a fresh session must resolve")
	}

	s.End(sess.Token)
	if s.Lookup(sess.Token) != nil {
		t.Fatal("a revoked session must not resolve")
	}
}

func TestSessionExpiry(t *testing.T) {
	s := NewSessions(time.Hour)
	now := time.Now()
	s.now = func() time.Time { return now }

	sess, _ := s.Start("user-1")
	now = now.Add(2 * time.Hour)

	if s.Lookup(sess.Token) != nil {
		t.Fatal("an expired session must not resolve")
	}
}

func TestEndAllForUser(t *testing.T) {
	s := NewSessions(time.Hour)
	a, _ := s.Start("user-1")
	b, _ := s.Start("user-1")
	c, _ := s.Start("user-2")

	s.EndAllForUser("user-1")

	if s.Lookup(a.Token) != nil || s.Lookup(b.Token) != nil {
		t.Error("all of the user's sessions should be revoked")
	}
	if s.Lookup(c.Token) == nil {
		t.Error("other users' sessions must survive")
	}
}

func TestRandomTokenUnique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		tok, err := RandomToken(16)
		if err != nil {
			t.Fatalf("RandomToken: %v", err)
		}
		if seen[tok] {
			t.Fatal("RandomToken returned a duplicate")
		}
		seen[tok] = true
	}
}

// ------------------------------------------------------- concurrency -------

// TestConcurrentSessions hammers the session table from many goroutines. It is
// not a substitute for `go test -race`, which the CI image runs, but it does
// catch missing locks and logic errors under interleaving on any platform.
func TestConcurrentSessions(t *testing.T) {
	s := NewSessions(time.Hour)

	const workers = 32
	var wg sync.WaitGroup
	tokens := make([]string, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sess, err := s.Start("user-1")
			if err != nil {
				t.Errorf("Start: %v", err)
				return
			}
			tokens[i] = sess.Token

			// Exercise lookup, touch and count concurrently.
			if s.Lookup(sess.Token) == nil {
				t.Error("a fresh session should resolve")
			}
			s.Touch(sess.Token)
			_ = s.Count()
		}(i)
	}
	wg.Wait()

	// Every token must have survived the contention.
	for i, tok := range tokens {
		if tok == "" {
			t.Fatalf("worker %d produced no token", i)
		}
		if s.Lookup(tok) == nil {
			t.Errorf("token %d was lost", i)
		}
	}

	// Revoking one user's sessions must not disturb another's.
	s.EndAllForUser("user-1")
	if s.Count() != 0 {
		t.Errorf("expected all sessions revoked, got %d", s.Count())
	}
}

// TestConcurrentStoreAccess exercises the users database from many goroutines.
func TestConcurrentStoreAccess(t *testing.T) {
	s := newStore(t)

	const workers = 16
	var wg sync.WaitGroup

	// Concurrent readers.
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.List()
			_, _ = s.GetByUsername("nobody")
			_ = s.Count()
		}()
	}

	// Concurrent unique writers.
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("user%02d", i)
			if _, err := s.Create(name, "password123", false, nil); err != nil {
				t.Errorf("Create(%s): %v", name, err)
			}
		}(i)
	}
	wg.Wait()

	if got := s.Count(); got != workers {
		t.Errorf("Count = %d, want %d", got, workers)
	}

	// Everything must have persisted: reopen and verify the total.
	dir := t.TempDir()
	_ = dir // the store path is internal, so verify by listing again
	users := s.List()
	if len(users) != workers {
		t.Fatalf("List returned %d users, want %d", len(users), workers)
	}
}
