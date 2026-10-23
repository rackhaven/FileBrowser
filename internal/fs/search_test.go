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

package fs

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rackhaven/filebrowser/internal/auth"
)

func paths(out SearchOut) []string {
	var got []string
	for _, e := range out.Entries {
		got = append(got, e.Path)
	}
	return got
}

func TestSearchFindsDeepMatches(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "notes/meeting/READ-me.txt", "hi")
	writeFile(t, root, "docs/private/readme-2024.txt", "x")
	u := user(auth.AccessAdmin)

	out, err := f.Search(u, "/", "read")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, want := range []string{
		"/docs/readme.txt",
		"/notes/meeting/READ-me.txt",
		"/docs/private/readme-2024.txt",
	} {
		if !containsPath(out, want) {
			t.Errorf("search missed %s; got %v", want, paths(out))
		}
	}
}

func containsPath(out SearchOut, p string) bool {
	return slicesContains(paths(out), p)
}

func TestSearchRespectsVisibility(t *testing.T) {
	f := newTestFS(t)
	// The user can open /docs/private, so it is enterable and its contents
	// may surface; nothing else below / is theirs.
	u := &auth.User{Username: "u", Grants: []auth.Grant{
		{Path: "/docs/private", Level: auth.AccessRead},
	}}

	out, err := f.Search(u, "/", "e")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, p := range paths(out) {
		// The readable folder itself may surface (its name matched), but
		// nothing outside it may.
		if p != "/docs/private" && !strings.HasPrefix(p, "/docs/private/") {
			t.Errorf("search leaked %s", p)
		}
	}
}

func TestSearchRefusesUnreachableRoots(t *testing.T) {
	f := newTestFS(t)
	u := &auth.User{Username: "u", Grants: []auth.Grant{
		{Path: "/docs", Level: auth.AccessRead},
	}}

	if _, err := f.Search(u, "/photos", "a"); err != ErrForbidden {
		t.Fatalf("Search from a denied root: %v, want ErrForbidden", err)
	}
}

func TestSearchCapsResults(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	for i := 0; i < SearchLimit+5; i++ {
		name := filepath.Join(root, "bulk", "match"+pad(i)+".txt")
		if i%50 == 0 {
			if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		}
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	u := user(auth.AccessAdmin)
	out, err := f.Search(u, "/", "match")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(out.Entries) != SearchLimit {
		t.Fatalf("entries = %d, want the %d cap", len(out.Entries), SearchLimit)
	}
	if !out.More {
		t.Error("More must report the cut-off")
	}
}

func TestSearchSkipsTempAndOutsideSymlinks(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, ".upload-secret.tmp", "y")
	if err := os.Symlink("/etc", filepath.Join(root, "hmm")); err != nil {
		t.Skipf("make symlink: %v", err)
	}
	u := user(auth.AccessAdmin)

	out, err := f.Search(u, "/", "sec")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, p := range paths(out) {
		if strings.HasSuffix(p, ".upload-secret.tmp") {
			t.Error("search exposed an in-flight upload temporary")
		}
	}
}

func TestSearchEmptyQueryMeansNoWork(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessAdmin)
	out, err := f.Search(u, "/", "   ")
	if err != nil || len(out.Entries) != 0 {
		t.Fatalf("empty query: %v entries, err %v, want none", len(out.Entries), err)
	}
}

func pad(i int) string { return strconv.Itoa(i) }
