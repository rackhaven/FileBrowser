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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
	u := user(auth.AccessWrite)

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
	u := user(auth.AccessWrite)

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
	u := user(auth.AccessWrite)

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
	u := user(auth.AccessWrite)

	// Targets of links inside the tree are written relative to the link, the
	// form the kernel's clamped resolution can follow all the way through;
	// see the containment note in the README about absolute targets.
	if err := os.Symlink("docs", filepath.Join(f.Root(), "docs-link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := f.Resolve(u, "/docs-link/readme.txt", auth.AccessRead); err != nil {
		t.Fatalf("symlink inside root should resolve: %v", err)
	}
	// The open goes through the same clamped walk and must succeed, so the
	// listing promise and the download promise agree.
	file, info, err := f.Open(u, "/docs-link/readme.txt")
	if err != nil {
		t.Fatalf("Open through an in-root symlink: %v", err)
	}
	if info.Name() != "readme.txt" {
		t.Errorf("Open named %q", info.Name())
	}
	file.Close()
}

// ------------------------------------------------------------------ ACL ----

func TestEffectiveLevelPicksLongestGrant(t *testing.T) {
	u := &auth.User{Grants: []auth.Grant{
		{Path: "/", Level: auth.AccessRead},
		{Path: "/photos", Level: auth.AccessWrite},
		{Path: "/photos/2024", Level: auth.AccessRead},
	}}

	tests := map[string]auth.AccessLevel{
		"/":                 auth.AccessRead,
		"/docs":             auth.AccessRead,
		"/photos":           auth.AccessWrite,
		"/photos/a/b":       auth.AccessWrite,
		"/photos/2024":      auth.AccessRead, // narrower rule wins, even downward
		"/photos/2024/trip": auth.AccessRead,
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
	if _, _, err := f.UploadTarget(readOnly, "/photos", "new.txt", false); err == nil {
		t.Error("upload with read-only access should fail")
	}

	writer := &auth.User{Grants: []auth.Grant{{Path: "/photos", Level: auth.AccessWrite}}}
	if _, err := f.Mkdir(writer, "/photos", "newdir"); err != nil {
		t.Errorf("mkdir with write access should work: %v", err)
	}
	if _, _, err := f.UploadTarget(writer, "/photos", "new.txt", false); err != nil {
		t.Errorf("upload with write access should work: %v", err)
	}

	// No grant at all is still denied.
	if _, err := f.Mkdir(writer, "/docs", "nope"); err == nil {
		t.Error("mkdir in a folder with no grant should fail")
	}
}

func TestRemoveRefusesRoot(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessWrite)
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
	entries, err := f.List(user(auth.AccessWrite), "/")
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

func TestUploadTargetRejectsCollisions(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessWrite)

	// An existing file is a conflict until the client asks to replace it.
	if _, _, err := f.UploadTarget(u, "/docs", "readme.txt", false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("upload over an unasked file = %v, want an existence error", err)
	}
	if _, _, err := f.UploadTarget(u, "/docs", "readme.txt", true); err != nil {
		t.Fatalf("upload over an acknowledged file = %v, want a destination", err)
	}
	if _, _, err := f.UploadTarget(u, "/docs", "private", false); !errors.Is(err, os.ErrExist) {
		t.Errorf("uploading onto a directory = %v", err)
	}
	if _, _, err := f.UploadTarget(u, "/docs", "private", true); !errors.Is(err, os.ErrExist) {
		t.Errorf("overwrite onto a directory = %v", err)
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
	if _, err := f.Rename(u, "/photos/a.jpg", "/docs", "stolen.jpg", false); err == nil {
		t.Fatal("rename from a read-only folder should fail")
	}
}

func TestInfoRejectsDirectoriesAsFiles(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessWrite)
	if _, _, err := f.Open(u, "/docs"); err == nil {
		t.Fatal("opening a directory as a file should fail")
	}
}

func TestOpenStreamsContent(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessWrite)

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

// ------------------------------------------------------------ upload temps ---

// In-flight uploads appear as .upload-* files in the served tree. They are
// private to the uploader for the seconds they exist: listings hide them and
// no mutation may be aimed at one.
func TestListHidesInFlightUploads(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessWrite)

	writeFile(t, mustRoot(f), ".upload-4ghost.tmp", "in flight")
	entries, err := f.List(u, "/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name, ".upload-") {
			t.Fatalf("listing exposed an in-flight upload: %s", e.Name)
		}
	}
	if got := len(entries); got == 0 {
		t.Fatal("listing came back empty, so nothing was actually hidden")
	}
}

func TestTempNamesAreReserved(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessWrite)
	writeFile(t, mustRoot(f), ".upload-refused.tmp", "x")

	if _, err := f.Mkdir(u, "/", ".upload-new"); err != ErrReserved {
		t.Errorf("mkdir with a reserved name: got %v, want ErrReserved", err)
	}
	if _, _, err := f.UploadTarget(u, "/", ".upload-froze.tmp", false); err != ErrReserved {
		t.Errorf("upload with a reserved name: got %v, want ErrReserved", err)
	}
	if err := f.Remove(u, "/.upload-refused.tmp"); err != ErrReserved {
		t.Errorf("remove a temp name: got %v, want ErrReserved", err)
	}
	if _, err := f.Rename(u, "/.upload-refused.tmp", "/", "gone.tmp", false); err != ErrReserved {
		t.Errorf("rename away from a temp name: got %v, want ErrReserved", err)
	}
	if _, err := f.Rename(u, "/docs/readme.txt", "/", ".upload-hijack.tmp", false); err != ErrReserved {
		t.Errorf("rename onto a temp name: got %v, want ErrReserved", err)
	}

	// The same operations with unreserved names keep working.
	if err := f.Remove(u, "/docs/readme.txt"); err != nil {
		t.Errorf("remove of an ordinary name: %v", err)
	}
}

// mustRoot returns the filesystem's real root, for planting temp files on
// disk directly (the API itself refuses to create them).
func mustRoot(f *FS) string { return f.Root() }

func TestSweepUploadTempsErasesAbandonedTemps(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)

	// A crashed upload leaves an unfinished temp file behind, wherever the
	// destination folder was.
	stale := filepath.Join(root, "docs", ".upload-crashed")
	if err := os.WriteFile(stale, []byte("half"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Copies and folder duplicates leave directories of the same prefix,
	// nested one level down where the copy landed.
	staleDir := filepath.Join(root, "photos", ".upload-copy-old")
	if err := os.Mkdir(staleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleDir, "part"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{stale, staleDir} {
		old := time.Now().Add(-26 * time.Hour)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	// A live upload is a temp the same age as the request it belongs to,
	// and everything ordinary keeps its name untouched.
	live := filepath.Join(root, ".upload-live")
	if err := os.WriteFile(live, []byte("streaming"), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := f.SweepUploadTemps(24 * time.Hour)
	if err != nil {
		t.Fatalf("SweepUploadTemps: %v", err)
	}
	if n != 2 {
		t.Fatalf("sweep removed %d, want 2", n)
	}
	if _, serr := os.Lstat(stale); !os.IsNotExist(serr) {
		t.Errorf("the crashed upload's temp survived: %v", serr)
	}
	if _, serr := os.Lstat(staleDir); !os.IsNotExist(serr) {
		t.Errorf("the abandoned copy directory survived: %v", serr)
	}
	if _, serr := os.Lstat(live); serr != nil {
		t.Errorf("the live upload's temp did not survive: %v", serr)
	}
	if _, serr := os.Stat(filepath.Join(root, "docs", "readme.txt")); serr != nil {
		t.Errorf("an ordinary file did not survive: %v", serr)
	}

	// Zero disables the sweep, and a second pass over the clean tree
	// removes nothing further.
	if n, err := f.SweepUploadTemps(0); err != nil || n != 0 {
		t.Fatalf("zero window must disable: n=%d err=%v", n, err)
	}
	if n, err := f.SweepUploadTemps(24 * time.Hour); err != nil || n != 0 {
		t.Fatalf("clean tree sweep: n=%d err=%v", n, err)
	}
}

func TestRenameOverwriteNeedsAsking(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessWrite)

	// Landing on a name already held conflicts, typed so the API layer
	// maps it to a status rather than a stack. Nothing else moved.
	if _, err := f.Rename(u, "/docs/readme.txt", "/photos/2024", "a.jpg", false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("blind overwrite = %v, want an existence error", err)
	}
	if _, serr := os.Stat(filepath.Join(mustRoot(f), "docs", "readme.txt")); serr != nil {
		t.Fatalf("the source did not survive the refusal: %v", serr)
	}
	if _, serr := os.Stat(filepath.Join(mustRoot(f), "photos", "2024", "a.jpg")); serr != nil {
		t.Fatalf("the collision target did not survive the refusal: %v", serr)
	}

	// Asked for, the move replaces the file wholesale.
	if _, err := f.Rename(u, "/docs/readme.txt", "/photos/2024", "a.jpg", true); err != nil {
		t.Fatalf("declared overwrite: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(mustRoot(f), "docs", "readme.txt")); !os.IsNotExist(serr) {
		t.Errorf("the source stayed put after a declared overwrite: %v", serr)
	}

	// A directory is never devoured, even on an explicit overwrite: a
	// single move replacing a whole subtree is deletion by common
	// mistake, not a rename ceremony. A second file was lost already if
	// this fails.
	if _, err := f.Rename(u, "/empty", "/", "photos", true); !errors.Is(err, os.ErrExist) {
		t.Errorf("overwrite onto a directory = %v, want an existence error", err)
	}
}

func TestUploadTargetOverwriteNeedsAsking(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessWrite)

	// An existing file is a conflict until the client says otherwise.
	if _, _, err := f.UploadTarget(u, "/photos/2024", "a.jpg", false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("blind upload overwrite = %v, want an existence error", err)
	}
	if _, _, err := f.UploadTarget(u, "/photos/2024", "a.jpg", true); err != nil {
		t.Fatalf("declared overwrite = %v, want a destination", err)
	}
	// A directory stays a conflict under both modes: a body has no way
	// to become a directory.
	if _, _, err := f.UploadTarget(u, "/", "docs", false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("upload onto a directory = %v, want an existence error", err)
	}
	if _, _, err := f.UploadTarget(u, "/", "docs", true); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrite onto a directory = %v, want an existence error", err)
	}
	// A fresh name takes no particular mode.
	if _, _, err := f.UploadTarget(u, "/photos", "new.png", false); err != nil {
		t.Fatalf("fresh destination = %v", err)
	}
}
