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
	"runtime"
	"testing"

	"github.com/rackhaven/filebrowser/internal/auth"
)

func newTestFS(t *testing.T) *FS {
	t.Helper()
	root := t.TempDir()

	// A realistic tree: nested dirs, a file, and an empty dir.
	mkdirAll(t, root, "photos/2024/trip")
	mkdirAll(t, root, "docs/private")
	mkdirAll(t, root, "empty")
	writeFile(t, root, "docs/readme.txt", "hello")
	writeFile(t, root, "photos/2024/a.jpg", "jpeg")
	writeFile(t, root, "docs/private/secret.txt", "classified")

	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

func mkdirAll(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(rel)), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func user(level auth.AccessLevel, grants ...auth.Grant) *auth.User {
	return &auth.User{Username: "u", Grants: append(grants, auth.Grant{Path: "/", Level: level})}
}

// ------------------------------------------------------------- traversal ---

// TestResolveRejectsTraversal is the core security test: no combination of
// traversal tricks may produce a path outside the root.
//
// Note that ".." at the root clamps to the root rather than erroring. That is
// deliberate and matches how a chroot behaves: "/../etc" means "<root>/etc",
// never the real /etc. The invariant under test is containment, not refusal.
func TestResolveRejectsTraversal(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessAdmin)

	cases := []string{
		"../",
		"../../",
		"../etc/passwd",
		"/../etc/passwd",
		"/docs/../../etc/passwd",
		"/docs/../..",
		"..",
		"/..",
		`..\..\windows`,
		`\..\..\windows`,
		"/./../",
		"/docs/./../../",
		"/////../../etc",
		"/docs//..//..//etc/passwd",
		"/../../../../../../etc/shadow",
	}

	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			got, err := f.Resolve(u, p, auth.AccessRead)
			if err != nil {
				return // refused outright, which is also fine
			}
			if !within(f.Root(), got) {
				t.Fatalf("traversal %q escaped the root: %q", p, got)
			}
		})
	}
}

// TestResolveClampsAboveRoot pins the documented behaviour: ".." at the top
// lands on the root rather than escaping.
func TestResolveClampsAboveRoot(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessAdmin)

	for _, p := range []string{"..", "/..", "/../..", "../../../../.."} {
		got, err := f.Resolve(u, p, auth.AccessRead)
		if err != nil {
			t.Fatalf("Resolve(%q) errored: %v", p, err)
		}
		if got != f.Root() {
			t.Errorf("Resolve(%q) = %q, want the root %q", p, got, f.Root())
		}
	}
}

// TestResolveRejectsSymlinkEscape covers the case a lexical check alone misses:
// a symlink inside the root pointing at /etc.
func TestResolveRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}

	f := newTestFS(t)
	u := user(auth.AccessAdmin)

	outside := t.TempDir()
	writeFile(t, outside, "secret.txt", "must not be reachable")

	link := filepath.Join(f.Root(), "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	for _, p := range []string{"/escape", "/escape/secret.txt"} {
		got, err := f.Resolve(u, p, auth.AccessRead)
		if err == nil {
			t.Fatalf("%q resolved to %q, want an error", p, got)
		}
	}

	// The listing must not hand out a usable path either.
	entries, err := f.List(u, "/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		if e.Name == "escape" {
			t.Fatalf("listing exposed an escaping symlink: %+v", e)
		}
	}
}

// TestResolveAllowsSymlinkInsideRoot checks we are not over-blocking: a symlink
// to a sibling inside the root is legitimate.
func TestResolveAllowsSymlinkInsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}

	f := newTestFS(t)
	u := user(auth.AccessAdmin)

	if err := os.Symlink(filepath.Join(f.Root(), "docs"), filepath.Join(f.Root(), "docs-link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := f.Resolve(u, "/docs-link/readme.txt", auth.AccessRead); err != nil {
		t.Fatalf("symlink inside root should resolve: %v", err)
	}
}

// ------------------------------------------------------------------ ACL ----

func TestEffectiveLevelPicksLongestGrant(t *testing.T) {
	u := &auth.User{Grants: []auth.Grant{
		{Path: "/", Level: auth.AccessRead},
		{Path: "/photos", Level: auth.AccessWrite},
		{Path: "/photos/2024", Level: auth.AccessAdmin},
	}}

	tests := map[string]auth.AccessLevel{
		"/":                 auth.AccessRead,
		"/docs":             auth.AccessRead,
		"/photos":           auth.AccessWrite,
		"/photos/a/b":       auth.AccessWrite,
		"/photos/2024":      auth.AccessAdmin,
		"/photos/2024/trip": auth.AccessAdmin,
		// "/photos-archive" must not inherit the "/photos" write grant. It only
		// matches the catch-all "/" read rule, so it stays read-only.
		"/photos-archive":      auth.AccessRead,
		"/photosx/2024":        auth.AccessRead,
		"/photos-archive/2024": auth.AccessRead,
	}
	for path, want := range tests {
		if got := u.EffectiveLevel(path); got != want {
			t.Errorf("EffectiveLevel(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestResolveDeniedOutsideGrants(t *testing.T) {
	f := newTestFS(t)
	u := &auth.User{Grants: []auth.Grant{{Path: "/photos", Level: auth.AccessRead}}}

	if _, err := f.Resolve(u, "/photos/a.jpg", auth.AccessRead); err != nil {
		t.Fatalf("granted path should resolve: %v", err)
	}
	for _, p := range []string{"/docs/readme.txt", "/docs/private/secret.txt", "/"} {
		if _, err := f.Resolve(u, p, auth.AccessRead); err == nil {
			t.Errorf("%q should be denied", p)
		}
	}
}

func TestWriteRequiresWriteGrant(t *testing.T) {
	f := newTestFS(t)

	readOnly := &auth.User{Grants: []auth.Grant{{Path: "/photos", Level: auth.AccessRead}}}
	// A read-only grant must not permit any mutation.
	if _, err := f.Mkdir(readOnly, "/photos", "newdir"); err == nil {
		t.Error("mkdir with read-only access should fail")
	}
	if err := f.Remove(readOnly, "/photos/a.jpg"); err == nil {
		t.Error("delete with read-only access should fail")
	}
	if _, _, err := f.UploadTarget(readOnly, "/photos", "new.txt"); err == nil {
		t.Error("upload with read-only access should fail")
	}

	writer := &auth.User{Grants: []auth.Grant{{Path: "/photos", Level: auth.AccessWrite}}}
	if _, err := f.Mkdir(writer, "/photos", "newdir"); err != nil {
		t.Errorf("mkdir with write access should work: %v", err)
	}
	if _, _, err := f.UploadTarget(writer, "/photos", "new.txt"); err != nil {
		t.Errorf("upload with write access should work: %v", err)
	}

	// No grant at all is still denied.
	if _, err := f.Mkdir(writer, "/docs", "nope"); err == nil {
		t.Error("mkdir in a folder with no grant should fail")
	}
}

func TestRemoveRefusesRoot(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessAdmin)
	if err := f.Remove(u, "/"); err == nil {
		t.Fatal("removing the root must be refused")
	}
	if _, err := os.Stat(f.realRoot); err != nil {
		t.Fatalf("root should still exist: %v", err)
	}
}

// ----------------------------------------------------------------- list ----

func TestListHidesInaccessibleEntries(t *testing.T) {
	f := newTestFS(t)
	u := &auth.User{Grants: []auth.Grant{{Path: "/photos", Level: auth.AccessRead}}}

	entries, err := f.List(u, "/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		if e.Name == "docs" {
			t.Fatalf("listing leaked a folder the user cannot access: %+v", e)
		}
	}
}

func TestListShowsPartialParents(t *testing.T) {
	f := newTestFS(t)
	// Granted only /docs/private: the "docs" parent must still appear, marked
	// partial, or the user could never navigate to the folder they own.
	u := &auth.User{Grants: []auth.Grant{{Path: "/docs/private", Level: auth.AccessRead}}}

	entries, err := f.List(u, "/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	var docs *Entry
	for i := range entries {
		if entries[i].Name == "docs" {
			docs = &entries[i]
		}
	}
	if docs == nil {
		t.Fatalf("docs should be listed as a partial parent, got %+v", entries)
	}
	if !docs.Partial {
		t.Error("expected docs to be flagged Partial")
	}
}

func TestListSortsDirsFirst(t *testing.T) {
	f := newTestFS(t)
	entries, err := f.List(user(auth.AccessAdmin), "/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	seenFile := false
	for _, e := range entries {
		if !e.IsDir {
			seenFile = true
		} else if seenFile {
			t.Fatalf("directory %q appeared after a file", e.Name)
		}
	}
}

func TestDisabledUserGetsNothing(t *testing.T) {
	f := newTestFS(t)
	u := &auth.User{Admin: true, Disabled: true}
	if _, err := f.List(u, "/"); err == nil {
		t.Fatal("a disabled account must not be able to browse")
	}
}

// ----------------------------------------------------------------- misc ----

func TestJoinRejectsTraversalNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../x", `a\b`, "x/y", "a\x00b"} {
		if got, err := Join("/docs", name); err == nil {
			t.Errorf("Join(%q) = %q, want an error", name, got)
		}
	}
	if got, err := Join("/docs", "ok.txt"); err != nil || got != "/docs/ok.txt" {
		t.Errorf("Join = %q, %v", got, err)
	}
	// The root case must not produce a double slash: "//docs" is a different
	// path for ACL matching and would silently hide root-level entries.
	if got, err := Join("/", "docs"); err != nil || got != "/docs" {
		t.Errorf(`Join("/", "docs") = %q, %v; want "/docs"`, got, err)
	}
	if got, err := Join("/", "a/b"); err == nil {
		t.Errorf(`Join with a slash = %q, want an error`, got)
	}
}

func TestCleanNormalises(t *testing.T) {
	tests := map[string]string{
		"":       "/",
		"/":      "/",
		"//":     "/",
		"/a/b/":  "/a/b",
		"a/b":    "/a/b",
		"/a//b":  "/a/b",
		"/a/./b": "/a/b",
		`\a\b`:   "/a/b",
		// path.Clean collapses ".." at the root, matching chroot semantics.
		"/a/b/../../": "/",
		"/a/b/../c":   "/a/c",
	}
	for in, want := range tests {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUploadTargetRejectsDirCollision(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessWrite)

	if _, _, err := f.UploadTarget(u, "/docs", "readme.txt"); err != nil {
		t.Fatalf("upload over a file should be allowed: %v", err)
	}
	if _, _, err := f.UploadTarget(u, "/docs", "private"); err == nil {
		t.Error("uploading onto a directory should be refused")
	}
}

func TestUsageTotalsOnlyGranted(t *testing.T) {
	f := newTestFS(t)
	u := &auth.User{Grants: []auth.Grant{{Path: "/photos", Level: auth.AccessRead}}}

	got, err := f.Usage(u, "/", 8)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	// /photos/a.jpg only: 4 bytes, 1 file. docs must not be counted.
	if got.Files != 1 {
		t.Errorf("Files = %d, want 1", got.Files)
	}
	if got.Bytes != 4 {
		t.Errorf("Bytes = %d, want 4", got.Bytes)
	}
}

func TestRenameRequiresWriteOnBothSides(t *testing.T) {
	f := newTestFS(t)
	u := &auth.User{Grants: []auth.Grant{
		{Path: "/photos", Level: auth.AccessRead},
		{Path: "/docs", Level: auth.AccessWrite},
	}}

	// Source is read-only, so the move must fail even though the target is
	// writable: otherwise a user could relocate files they cannot read.
	if _, err := f.Rename(u, "/photos/a.jpg", "/docs", "stolen.jpg"); err == nil {
		t.Fatal("rename from a read-only folder should fail")
	}
}

func TestInfoRejectsDirectoriesAsFiles(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessAdmin)
	if _, _, err := f.Open(u, "/docs"); err == nil {
		t.Fatal("opening a directory as a file should fail")
	}
}

func TestOpenStreamsContent(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessAdmin)

	file, _, err := f.Open(u, "/docs/readme.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer file.Close()

	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	if _, err := file.Read(buf); err != nil && len(buf) == 0 {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("content = %q", buf)
	}
}
