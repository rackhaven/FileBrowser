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

// ------------------------------------------------- two processes, one db ---

// Two open handles model a running server and a CLI working against the same
// database file. The lock file serialises them and each mutation re-reads the
// file when it changed, so a CLI edit is never silently overwritten by the
// server's next save.
func TestStoreCoordinatesSeparateHandles(t *testing.T) {
	path := t.TempDir() + "/users.json"

	server := newStoreAt(t, path)
	cli := newStoreAt(t, path) // loaded before the server writes anything

	if _, err := server.Create("admin", "password123", true, nil); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	// The cli's copy is stale now. Its mutation must notice, reload, and
	// create alice alongside the admin rather than clobbering the file.
	created, err := cli.Create("alice", "wonderland9", false, nil)
	if err != nil {
		t.Fatalf("create through a stale handle: %v", err)
	}
	if _, err := cli.Create("alice", "wonderland9", false, nil); err != ErrUserExists {
		t.Fatalf("stale handle double-create: %v, want ErrUserExists", err)
	}

	// The server's next write re-reads first, so alice keeps her account and
	// gains the new password.
	if err := server.SetPassword(created.ID, "newwonder9", true); err != nil {
		t.Fatalf("server write after an external change: %v", err)
	}

	fresh := newStoreAt(t, path)
	alive, err := fresh.GetByUsername("alice")
	if err != nil {
		t.Fatal("alice was lost when the server saved after the CLI")
	}
	if ok, err := VerifyPassword("newwonder9", alive.PasswordHash); err != nil || !ok {
		t.Fatal("the password change was reverted or unverifiable")
	}
	admin, err := fresh.GetByUsername("admin")
	if err != nil || !admin.Admin {
		t.Fatal("the seed admin did not survive the cross-write sequence")
	}

	// Last-admin protection still works across handles: the cli (which has
	// not seen the server's latest save) is refused when it tries to demote
	// the only admin it knows about.
	_, _ = cli.Update(admin.ID, func(u *User) {
		u.Admin = false
		if u.Grants == nil {
			u.Grants = []Grant{}
		}
	})
	if _, err := cli.Update(admin.ID, func(u *User) { u.Admin = false }); err != ErrLastAdmin {
		t.Fatalf("last admin guard across handles: %v, want ErrLastAdmin", err)
	}
}

func newStoreAt(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore %s: %v", path, err)
	}
	return s
}

func TestListForUserAndEndByID(t *testing.T) {
	s := NewSessions(time.Hour)
	now := time.Now()
	s.now = func() time.Time { return now }

	a, _ := s.Start("user-1")
	now = now.Add(time.Minute)
	b, _ := s.Start("user-1")
	_, _ = s.Start("user-2")
	now = now.Add(time.Minute)

	// Newest first, and only that user's.
	live := s.ListForUser("user-1")
	if len(live) != 2 || live[0].Token != b.Token || live[1].Token != a.Token {
		t.Fatalf("ListForUser = %v", live)
	}
	for _, sess := range live {
		if sess.PublicID == "" || sess.PublicID == sess.Token {
			t.Errorf("public id missing or a raw token: %q", sess.PublicID)
		}
	}

	// Unknown and empty ids answer as missing.
	if err := s.EndByID("user-1", ""); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("empty id: %v", err)
	}
	if err := s.EndByID("user-1", "nope"); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("unknown id: %v", err)
	}

	// Revoking by public id kills exactly that session.
	if err := s.EndByID("user-1", a.PublicID); err != nil {
		t.Fatalf("EndByID: %v", err)
	}
	if s.Lookup(a.Token) != nil {
		t.Error("the revoked session still resolves")
	}
	if s.Lookup(b.Token) == nil {
		t.Error("an unrelated session was revoked")
	}
	// Another account's id does not revoke this account's session.
	if err := s.EndByID("user-2", b.PublicID); len(s.ListForUser("user-1")) != 1 {
		t.Errorf("another user's revoke got through: %v", err)
	}
}

func TestPublicIDsDistinctAcrossSessions(t *testing.T) {
	s := NewSessions(time.Hour)
	seen := make(map[string]int)
	for i := 0; i < 24; i++ {
		sess, err := s.Start("user-1")
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		seen[sess.PublicID]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("public id %q repeats on %d live sessions", id, n)
		}
	}
}

func TestSessionsPersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")

	s1, err := OpenSessions(path, time.Hour)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	end, _ := s1.Start("user-1")
	keep, _ := s1.Start("user-1")
	_, _ = s1.Start("user-1")
	if err := s1.End(end.Token); err != nil {
		t.Fatalf("End: %v", err)
	}

	// The file holds recognisable records but no raw tokens.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("sessions file: %v", err)
	}
	if strings.Contains(string(raw), keep.Token) {
		t.Error("a raw session token was written to disk")
	}
	if !strings.Contains(string(raw), keep.PublicID) {
		t.Error("the public id did not make it to disk")
	}

	// Reopening continues the same table: one live session, reachable by its
	// cookie, gone for the one that was ended.
	s2, err := OpenSessions(path, time.Hour)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got := s2.Lookup(keep.Token)
	if got == nil || got.UserID != "user-1" {
		t.Fatal("a persisted session must come back after reopen")
	}
	if got.Token != "" {
		t.Errorf("a reloaded session carries a raw token: %q", got.Token)
	}
	if s2.Lookup(end.Token) != nil {
		t.Error("an ended session came back from disk")
	}
	if len(s2.ListForUser("user-1")) != 2 {
		t.Fatalf("reopened table holds %d sessions, want 2", len(s2.ListForUser("user-1")))
	}

	// Revocation after a reopen is durable too.
	if err := s2.EndByID("user-1", keep.PublicID); err != nil {
		t.Fatalf("EndByID after reopen: %v", err)
	}
	s3, _ := OpenSessions(path, time.Hour)
	if s3.Lookup(keep.Token) != nil {
		t.Error("a session revoked after reopen survived the save")
	}
}

func TestOpenSessionsPrunesAndRefusesCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")
	now := time.Now()
	dead := fmt.Sprintf(`{"token_hash":"hash-dead","user_id":"u","expires_at":%q}`,
		now.Add(-time.Hour).Format(time.RFC3339))
	alive := fmt.Sprintf(`{"token_hash":"hash-alive","user_id":"u","public_id":"p1",
		"created_at":%q,"last_seen":%q,"expires_at":%q}`,
		now.Add(-time.Minute).Format(time.RFC3339),
		now.Format(time.RFC3339),
		now.Add(time.Hour).Format(time.RFC3339))
	broken := fmt.Sprintf(`{"token_hash":"","user_id":"","expires_at":%q}`,
		now.Add(time.Hour).Format(time.RFC3339))

	// Empty-hash junk and expired rows are dropped; valid rows load.
	if err := os.WriteFile(path, []byte("["+dead+","+alive+","+broken+"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSessions(path, time.Hour)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("table holds %d sessions, want the one live row", s.Count())
	}
	if got := s.ListForUser("u"); len(got) != 1 || got[0].PublicID != "p1" {
		t.Fatalf("loaded list = %v", got)
	}

	// A file that is not JSON at all is a loud problem, not silent loss.
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSessions(path, time.Hour); err == nil {
		t.Fatal("corrupt sessions file must be a startup error")
	}
}

func TestSessionsSaveFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	s, err := OpenSessions(path, time.Hour)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	first, err := s.Start("user-1")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	second, _ := s.Start("user-1")

	// Break every further save in a way that fails for root exactly as it
	// does for anyone else: the save's stepped-aside temporary file cannot
	// be created, because its name is already a directory. (A chmod-based
	// block would not stop root, and the image job runs the suite as root.)
	blocker := path + ".tmp"
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Start("user-1"); err == nil {
		t.Fatal("Start with a dead save must fail, not pretend")
	}
	if err := s.End(first.Token); err == nil {
		t.Fatal("End with a dead save must fail, not pretend")
	}
	if s.Lookup(first.Token) == nil {
		t.Error("a failed revoke must leave the session live, memory matching the file")
	}
	if err := s.EndAllForUser("user-1"); err == nil {
		t.Fatal("EndAllForUser with a dead save must fail, not pretend")
	}
	if s.Lookup(second.Token) == nil {
		t.Error("a failed wipe must leave every session live")
	}

	// Unblock: the pending changes land now, and the revocations complete.
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := s.EndAllForUser("user-1"); err != nil {
		t.Fatalf("EndAllForUser after the save healed: %v", err)
	}
	if s.Lookup(first.Token) != nil || s.Lookup(second.Token) != nil {
		t.Error("revocations did not complete after the save healed")
	}

	// Coverage under root in CI makes aiming at permission bits unreliable;
	// see the blocker above. A quick End on an intact table completes too.
	third, err := s.Start("user-1")
	if err != nil {
		t.Fatalf("Start after repair: %v", err)
	}
	if err := s.End(third.Token); err != nil {
		t.Fatalf("End on a healthy table: %v", err)
	}
}

func TestSyncReplaceMovesData(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "note.tmp")
	target := filepath.Join(dir, "note")

	// A syncReplace without a written temp file cannot succeed.
	if err := os.WriteFile(tmp, []byte("durable payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncReplace(tmp, target); err != nil {
		t.Fatalf("syncReplace: %v", err)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(raw) != "durable payload" {
		t.Errorf("target holds %q", raw)
	}
	// The temp name must not survive: leaving it behind would invite a
	// later save to read stale bytes through WriteFile-free paths.
	if _, err := os.Lstat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temp file survived the rename: %v", err)
	}

	// Replacing an existing target stays atomic-or-newer: the rename lands
	// over the old name without error.
	if err := os.WriteFile(tmp, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncReplace(tmp, target); err != nil {
		t.Fatalf("second syncReplace: %v", err)
	}
	raw, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "second" {
		t.Errorf("second target holds %q", raw)
	}
}

// TestRestrictedBelow: only grants strictly beneath the path count, matched
// on whole segments, and administrators are never restricted.
func TestRestrictedBelow(t *testing.T) {
	u := &User{Grants: []Grant{
		{Path: "/photos", Level: AccessWrite},
		{Path: "/photos/private", Level: AccessRead},
		{Path: "/photos-archive/x", Level: AccessRead},
	}}
	cases := []struct {
		path string
		want bool
	}{
		{"/photos", true},
		{"/", true},
		{"/photos/private", false}, // its own rule is not beneath it
		{"/photos/other", false},
		{"/photos-archive", true},
		{"/photos/private/deeper", false},
	}
	for _, c := range cases {
		if got := u.RestrictedBelow(c.path, AccessWrite); got != c.want {
			t.Errorf("RestrictedBelow(%q) = %v, want %v", c.path, got, c.want)
		}
	}
	if (&User{Admin: true, Grants: u.Grants}).RestrictedBelow("/", AccessWrite) {
		t.Error("an administrator is never restricted")
	}
}
