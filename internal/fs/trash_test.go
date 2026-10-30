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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// adminUser is a real server admin (the boolean, as the login flow sets it).
// The grant helpers below cannot express this: grants give read or write,
// and administration comes only from the account's admin flag.
func adminUser() *auth.User {
	return &auth.User{Username: "admin", Admin: true}
}

func trashItem(t *testing.T, f *FS) TrashEntry {
	t.Helper()
	entries, err := f.TrashList(adminUser())
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("trash holds %d entries, want 1", len(entries))
	}
	return entries[0]
}

func TestRemoveMovesToTrash(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "docs/readme.txt", "hello")
	if err := os.MkdirAll(filepath.Join(root, "docs", "depth"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "docs/depth/leaf.txt", "leaf")
	u := adminUser()

	if err := f.Remove(u, "/docs"); err != nil {
		t.Fatalf("Remove /docs: %v", err)
	}
	// The listing no longer shows the folder or the trash machinery...
	if _, err := f.List(u, "/"); err != nil {
		t.Fatalf("List /: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "docs")); !os.IsNotExist(err) {
		t.Errorf("source still on disk: %v", err)
	}

	entry := trashItem(t, f)
	if entry.OriginalPath != "/docs" || !entry.IsDir || entry.DeletedBy != "admin" {
		t.Fatalf("entry = %+v", entry)
	}
	// ...but the bytes are physically there, under the reserved name.
	if _, err := os.Lstat(filepath.Join(root, trashDirName, filepath.Base(entry.Name))); err != nil {
		t.Errorf("trashed tree missing on disk: %v", err)
	}
}

func TestRestoreReturnsToTheOriginalPlace(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "docs/readme.txt", "hello")
	u := adminUser()

	if err := f.Remove(u, "/docs/readme.txt"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := f.RestoreTrash(u, trashItem(t, f).Name); err != nil {
		t.Fatalf("RestoreTrash: %v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(root, "docs", "readme.txt")); err != nil || string(raw) != "hello" {
		t.Errorf("restored file: %q err %v", raw, err)
	}
	entries, _ := f.TrashList(u)
	if len(entries) != 0 {
		t.Errorf("trash still holds %d entries; want empty", len(entries))
	}
}

func TestRestoreRecreatesVanishedParents(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "deep/nest/keep.txt", "x")
	u := adminUser()

	// Both the folder and its parent are gone by the time restore runs.
	if err := f.Remove(u, "/deep/nest"); err != nil {
		t.Fatalf("Remove nest: %v", err)
	}
	if err := f.Remove(u, "/deep"); err != nil {
		t.Fatalf("Remove deep: %v", err)
	}
	entries, err := f.TrashList(u)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.OriginalPath != "/deep/nest" {
			continue
		}
		if err := f.RestoreTrash(u, e.Name); err != nil {
			t.Fatalf("RestoreTrash after parent removal: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "deep", "nest")); err != nil {
		t.Errorf("nested folders not recreated: %v", err)
	}
}

func TestRestoreConflictAndVisibility(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "docs/readme.txt", "first")
	u := adminUser()

	if err := f.Remove(u, "/docs/readme.txt"); err != nil {
		t.Fatal(err)
	}
	// Something now occupies the original slot: restore must fail cleanly.
	writeFile(t, root, "docs/readme.txt", "newer")
	if err := f.RestoreTrash(u, trashItem(t, f).Name); !isExistError(err) {
		t.Errorf("restore over an existing entry: %v, want an exists error", err)
	}

	// Visibility: a user with write access at /docs sees and can restore it.
	writer := user(auth.AccessNone, auth.Grant{Path: "/docs", Level: auth.AccessWrite})
	seen, err := f.TrashList(writer)
	if err != nil || len(seen) != 1 || !seen[0].CanRestore {
		t.Errorf("writer's trash list: %v err %v, want one restorable entry", seen, err)
	}

	// Straight reads are not enough: a read-only user sees nothing at all.
	reader := user(auth.AccessNone, auth.Grant{Path: "/docs", Level: auth.AccessRead})
	seen, err = f.TrashList(reader)
	if err != nil || len(seen) != 0 {
		t.Errorf("reader's trash list: %v err %v, want empty", seen, err)
	}
}

func isExistError(err error) bool {
	return err != nil && (err == os.ErrExist || errIs(os.ErrExist, err))
}

func errIs(target, err error) bool {
	for target != nil && err != nil {
		if err == target {
			return true
		}
		return false // errors.Is semantics without importing errors here
	}
	return false
}

func TestTrashDeleteAndPurge(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "one.txt", "1")
	writeFile(t, root, "two.txt", "2")
	u := adminUser()

	if err := f.Remove(u, "/one.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.TrashDelete(u, trashItem(t, f).Name); err != nil {
		t.Fatalf("TrashDelete: %v", err)
	}
	if entries, _ := f.TrashList(u); len(entries) != 0 {
		t.Fatalf("TrashDelete left %d entries", len(entries))
	}

	if err := f.Remove(u, "/two.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.TrashPurge(adminUser()); err != nil {
		t.Fatalf("TrashPurge: %v", err)
	}
	if _, err := os.ReadDir(filepath.Join(root, trashDirName)); err != nil {
		t.Fatalf("trash dir after purge: %v", err)
	}
	entries, _ := f.TrashList(u)
	if len(entries) != 0 {
		t.Errorf("purged trash still lists %d", len(entries))
	}

	// Purge is admin-only even though the list handler is not.
	if err := f.TrashPurge(user(auth.AccessRead)); err == nil {
		t.Error("TrashPurge by a non-admin succeeded")
	}
}

func TestReservedTrashNameCannotBeUsed(t *testing.T) {
	f := newTestFS(t)
	u := adminUser()

	if _, err := f.Mkdir(u, "/", ".trash"); err != ErrReserved {
		t.Errorf("Mkdir .trash: %v, want ErrReserved", err)
	}
	if _, err := f.Rename(u, "/docs", "/", ".trash", false); err != ErrReserved {
		t.Errorf("Rename to .trash: %v, want ErrReserved", err)
	}
	if err := f.Remove(u, "/.trash"); err != ErrReserved {
		t.Errorf("Remove /%s: %v, want ErrReserved", trashDirName, err)
	}
	// Listings never offer it either way.
	entries, err := f.List(u, "/")
	if err != nil {
		t.Fatalf("List /: %v", err)
	}
	for _, e := range entries {
		if e.Name == trashDirName {
			t.Error("listing exposed the trash directory")
		}
	}
}

func TestRestoreDeniedForOutsiders(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "photos/mine.txt", "x")
	admin := adminUser()
	if err := f.Remove(admin, "/photos/mine.txt"); err != nil {
		t.Fatal(err)
	}
	entry := trashItem(t, f)

	// An unrelated user cannot restore or shred what they cannot write at.
	outsider := user(auth.AccessNone, auth.Grant{Path: "/docs", Level: auth.AccessWrite})
	if err := f.RestoreTrash(outsider, entry.Name); err != ErrForbidden {
		t.Errorf("outsider restore: %v, want ErrForbidden", err)
	}
	if err := f.TrashDelete(outsider, entry.Name); err != ErrForbidden {
		t.Errorf("outsider shred: %v, want ErrForbidden", err)
	}
	// Garbage names answer as missing, never as panics.
	if err := f.RestoreTrash(admin, ""); err != ErrNotExist {
		t.Errorf("empty name: %v, want ErrNotExist", err)
	}
	if err := f.RestoreTrash(admin, "../escape"); err != ErrNotExist {
		t.Errorf("traversal name: %v, want ErrNotExist", err)
	}
}

// -------------------------------------------------------------- copies ---

func TestCopyFileAndFolder(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "docs/readme.txt", "hello")
	writeFile(t, root, "docs/deep/a.txt", "a")
	writeFile(t, root, "docs/deep/b.txt", "b")
	u := adminUser()

	// A file becomes an independent file.
	file, err := f.Copy(u, "/docs/readme.txt", "/", "readme-copy.txt")
	if err != nil {
		t.Fatalf("Copy file: %v", err)
	}
	if file.IsDir || file.Path != "/readme-copy.txt" || file.Size != 5 {
		t.Fatalf("copy entry = %+v", file)
	}
	if raw, rerr := os.ReadFile(filepath.Join(root, "readme-copy.txt")); rerr != nil || string(raw) != "hello" {
		t.Errorf("copied bytes: %q err %v", raw, rerr)
	}
	// Independence: changing the original must not reach the copy.
	writeFile(t, root, "docs/readme.txt", "changed")
	if raw, _ := os.ReadFile(filepath.Join(root, "readme-copy.txt")); string(raw) != "hello" {
		t.Errorf("copy moved with the original: %q", raw)
	}

	// A folder becomes an independent subtree. Copying a folder from inside
	// itself is a legal and useful ask, and must terminate.
	dir, err := f.Copy(u, "/docs", "/docs", "docs-copy")
	if err != nil {
		t.Fatalf("Copy folder into itself: %v", err)
	}
	if !dir.IsDir || dir.Path != "/docs/docs-copy" {
		t.Fatalf("copy entry = %+v", dir)
	}
	// Shares the rewrite from between the two copies: independence applies
	// to the root-level file copy above, and this copy was made after it.
	for p, want := range map[string]string{
		"docs/docs-copy/readme.txt": "changed",
		"docs/docs-copy/deep/a.txt": "a",
		"docs/docs-copy/deep/b.txt": "b",
	} {
		if raw, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(p))); rerr != nil || string(raw) != want {
			t.Errorf("%s: %q err %v", p, raw, rerr)
		}
	}

	// Listings show the copy with the machinery hidden.
	entries, lerr := f.List(u, "/")
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, e := range entries {
		if isUploadTempName(e.Name) || e.Name == trashDirName {
			t.Errorf("listing exposed reserved machinery: %q", e.Name)
		}
	}
}

func TestCopyRefusesAndPermissions(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "docs/readme.txt", "hello")
	// The existing destination lives at the root, beside the photos dir.
	writeFile(t, root, "readme.txt", "root file")
	writeFile(t, root, "photos/a.jpg", "JPEG")
	u := adminUser()

	// Existing destination: a copy is a create, never a replace.
	if _, err := f.Copy(u, "/docs/readme.txt", "/", "readme.txt"); !errors.Is(err, os.ErrExist) {
		t.Errorf("copy onto existing name: %v, want exists error", err)
	}

	// Reserved names cannot be sources or destinations.
	if _, err := f.Copy(u, "/.trash", "/", "x"); err != ErrReserved && !errors.Is(err, ErrReserved) {
		t.Errorf("copy from a reserved base: %v, want ErrReserved", err)
	}
	if _, err := f.Copy(u, "/docs", "/", ".upload-copy"); err != ErrReserved {
		t.Errorf("copy into a reserved name: %v, want ErrReserved", err)
	}
	if _, err := f.Copy(u, "/", "/", "root-copy"); err == nil {
		t.Error("copying the root succeeded")
	}

	// An empty name defaults to the source's own name, landing the copy
	// beside the original under a fresh directory.
	if err := os.MkdirAll(filepath.Join(root, "goes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Copy(u, "/docs/readme.txt", "/goes", ""); err != nil {
		t.Errorf("copy with default name: %v", err)
	}
	if raw, rerr := os.ReadFile(filepath.Join(root, "goes", "readme.txt")); rerr != nil || string(raw) != "hello" {
		t.Errorf("default-name copy: %q err %v", raw, rerr)
	}

	// The reader/writer split: read on the source and write on the target
	// are both required.
	reader := user(auth.AccessNone, auth.Grant{Path: "/docs", Level: auth.AccessRead})
	if _, err := f.Copy(reader, "/docs/readme.txt", "/goes", "no.txt"); err != ErrForbidden {
		t.Errorf("copy without write on target: %v, want ErrForbidden", err)
	}
	writer := user(auth.AccessNone, auth.Grant{Path: "/goes", Level: auth.AccessWrite})
	if _, err := f.Copy(writer, "/docs/readme.txt", "/goes", "also.txt"); err != ErrForbidden {
		t.Errorf("copy without read on source: %v, want ErrForbidden", err)
	}
	both := user(auth.AccessNone,
		auth.Grant{Path: "/docs", Level: auth.AccessRead},
		auth.Grant{Path: "/goes", Level: auth.AccessWrite})
	if _, err := f.Copy(both, "/docs/readme.txt", "/goes", "ok.txt"); err != nil {
		t.Errorf("copy with both grants: %v", err)
	}

	// Nothing of the copied tree may have polluted the source's siblings.
	if _, err := os.Stat(filepath.Join(root, "docs", "readme.txt")); err != nil {
		t.Errorf("source changed: %v", err)
	}
}

func TestCopySymlinkPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "pile/note.txt", "note")

	// Links in the pile: one to an in-root file, one to an in-root folder,
	// and one folder link plus one file link reaching outside the root.
	if err := os.Symlink("note.txt", filepath.Join(root, "pile", "file-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../docs", filepath.Join(root, "pile", "docs-link")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(root), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("classified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "pile", "outlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside/secret.txt", filepath.Join(root, "pile", "escape-file")); err != nil {
		t.Fatal(err)
	}

	u := adminUser()
	if _, err := f.Copy(u, "/pile", "/docs", "mixed"); err != nil {
		t.Fatalf("Copy pile: %v", err)
	}

	// Carried through: plain files and the content of in-root file links.
	for rel, want := range map[string]string{
		"docs/mixed/note.txt":  "note",
		"docs/mixed/file-link": "note",
	} {
		if raw, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))); rerr != nil || string(raw) != want {
			t.Errorf("%s: %q err %v", rel, raw, rerr)
		}
	}

	// Never carried: folder links, even harmless ones into the root
	// (copying never walks a folder link, so a cycle layout cannot spin),
	// and anything reaching outside the root.
	for _, rel := range []string{
		"docs/mixed/docs-link",
		"docs/mixed/outlink",
		"docs/mixed/escape-file",
	} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Errorf("%s should not be in the copy: %v", rel, err)
		}
	}
}

func TestTrashSweepErasesByAge(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	u := adminUser()

	mk := func(rel string) {
		writeFile(t, root, rel, "x")
		if err := f.Remove(u, "/"+rel); err != nil {
			t.Fatalf("Remove %s: %v", rel, err)
		}
	}
	mk("old.txt")
	mk("young.txt")
	mk("guess.txt") // its record gets wiped below, becoming recordless

	// Backdate one sidecar well past the window and blank another's
	// DeletedAt, treating it as older than every window.
	trash := filepath.Join(root, trashDirName)
	oldItem := ""
	for _, entry := range mustTrashList(t, f) {
		switch {
		case strings.HasSuffix(entry.Name, "-old.txt"):
			oldItem = entry.Name
			backdateTrashRecord(t, trash, entry.Name, 40*24*time.Hour)
		case strings.HasSuffix(entry.Name, "-guess.txt"):
			// A record with no DeletedAt field: zero answers as ancient.
			id := trashIDOf(entry.Name)
			if err := os.WriteFile(filepath.Join(trash, "."+id+".json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if oldItem == "" {
		t.Fatal("the old entry did not make it to the trash")
	}
	// A recordless item: an entry whose sidecar vanishes is skipped by
	// listings and must also be skipped by the sweep, never guessed at.
	if err := os.MkdirAll(filepath.Join(root, "parked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(u, "/parked"); err != nil {
		t.Fatal(err)
	}
	var parked string
	for _, entry := range mustTrashList(t, f) {
		if strings.HasSuffix(entry.Name, "-parked") {
			parked = entry.Name
			id := trashIDOf(entry.Name)
			if err := os.Remove(filepath.Join(trash, "."+id+".json")); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if parked == "" {
		t.Fatal("the recordless entry did not make it to the trash")
	}

	n, err := f.TrashSweep(30 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("TrashSweep: %v", err)
	}
	// Two: the backdated one, and the one whose record lost its DeletedAt
	// (zero answers as ancient). The recordless parked entry is out of
	// the sweep's reach on purpose: no record, no knowable age, no guess.
	if n != 2 {
		t.Fatalf("sweep removed %d entries, want 2", n)
	}
	// The old one is gone, item and record.
	if _, serr := os.Stat(filepath.Join(trash, oldItem)); !os.IsNotExist(serr) {
		t.Errorf("the old entry survived: %v", serr)
	}
	// The young one is untouched.
	for _, entry := range mustTrashList(t, f) {
		if !strings.HasSuffix(entry.Name, "-young.txt") {
			t.Errorf("unexpected survivor in the listing: %q", entry.Name)
		}
	}
	// The recordless one is still parked under its own name.
	if _, serr := os.Stat(filepath.Join(trash, parked)); serr != nil {
		t.Errorf("the recordless entry was not left alone: %v", serr)
	}

	// A zero window means retention is off: the sweep is a no-op.
	if n, err := f.TrashSweep(0); err != nil || n != 0 {
		t.Fatalf("off retention did not pass through untouched: n=%d err=%v", n, err)
	}
	if len(mustTrashList(t, f)) != 1 {
		t.Error("a zero window removed something")
	}
}

func TestTrashSweepIsANoOpWithoutATrashDirectory(t *testing.T) {
	f := newTestFS(t) // nothing deleted yet
	if n, err := f.TrashSweep(24 * time.Hour); err != nil || n != 0 {
		t.Fatalf("sweep on quiet server: n=%d err=%v", n, err)
	}
}

// ------------------------------------------------------------ helpers ---

func mustTrashList(t *testing.T, f *FS) []TrashEntry {
	t.Helper()
	entries, err := f.TrashList(adminUser())
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	return entries
}

// backdateTrashRecord rewrites a sidecar so the entry reads as if it had
// been deleted that long ago.
func backdateTrashRecord(t *testing.T, trash, item string, age time.Duration) {
	t.Helper()
	id := trashIDOf(item)
	if id == "" {
		t.Fatalf("no id in %q", item)
	}
	raw, err := os.ReadFile(filepath.Join(trash, "."+id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta TrashMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	meta.DeletedAt = time.Now().UTC().Add(-age)
	raw, err = json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trash, "."+id+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
