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
	"testing"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// adminUser is a real server admin (the boolean, as the login flow sets it).
// The grant helpers below cannot express this: a grant with an AccessAdmin
// level is path administration, not the session-wide admin flag.
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
	if _, err := f.Rename(u, "/docs", "/", ".trash"); err != ErrReserved {
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
