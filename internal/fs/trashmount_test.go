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
	"strings"
	"testing"
	"time"
)

// newMountedFS lays out a root holding /disk, which the test pretends is a
// separate mount: real nested mounts need privileges a test does not have.
func newMountedFS(t *testing.T) (*FS, string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "disk/album/a.jpg", "photo")
	writeFile(t, root, "disk/notes.txt", "note")
	writeFile(t, root, "home.txt", "on the root disk")
	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	disk := filepath.Join(f.Root(), "disk")
	old := mountID
	mountID = func(p string) (uint64, bool) {
		if within(disk, p) {
			return 2, true
		}
		return 1, true
	}
	t.Cleanup(func() { mountID = old })
	return f, f.Root()
}

// TestDeleteOnAMountUsesItsOwnTrash: the item lands in the disk's own
// trash by rename (the same inode, not a copy), lists with its real trash
// path, and restores the same way.
func TestDeleteOnAMountUsesItsOwnTrash(t *testing.T) {
	f, root := newMountedFS(t)
	before, err := os.Stat(filepath.Join(root, "disk/album"))
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Remove(adminUser(), "/disk/album"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	entries := mustTrashList(t, f)
	if len(entries) != 1 || !strings.HasPrefix(entries[0].TrashPath, "/disk/.trash/") {
		t.Fatalf("trash = %+v, want one entry under /disk/.trash", entries)
	}
	inTrash, err := os.Stat(filepath.Join(root, "disk", trashDirName, entries[0].Name))
	if err != nil {
		t.Fatalf("item not in the disk's trash: %v", err)
	}
	if !os.SameFile(before, inTrash) {
		t.Fatal("the item was copied, not renamed, into the trash")
	}
	if reg := f.readRegistry(); len(reg.Mounts) != 1 || reg.Mounts[0] != "/disk" {
		t.Fatalf("registry = %+v, want [/disk]", reg.Mounts)
	}

	if err := f.RestoreTrash(adminUser(), entries[0].Name); err != nil {
		t.Fatalf("RestoreTrash: %v", err)
	}
	after, err := os.Stat(filepath.Join(root, "disk/album"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("restore did not rename the folder back: %v", err)
	}

	// Deletes from the root's own disk keep using the root's trash.
	if err := f.Remove(adminUser(), "/home.txt"); err != nil {
		t.Fatalf("Remove on the root disk: %v", err)
	}
	entries = mustTrashList(t, f)
	if len(entries) != 1 || !strings.HasPrefix(entries[0].TrashPath, "/.trash/") {
		t.Fatalf("root-disk delete went to %+v, want /.trash", entries)
	}
}

// TestMountTrashEraseSweepAndPurge: every way out of the trash reaches the
// disk's trash too, and erasing everything keeps the registry.
func TestMountTrashEraseSweepAndPurge(t *testing.T) {
	f, root := newMountedFS(t)
	if err := f.Remove(adminUser(), "/disk/album"); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(adminUser(), "/disk/notes.txt"); err != nil {
		t.Fatal(err)
	}
	diskTrash := filepath.Join(root, "disk", trashDirName)

	var album, notes string
	for _, e := range mustTrashList(t, f) {
		if strings.HasSuffix(e.Name, "-album") {
			album = e.Name
		} else {
			notes = e.Name
		}
	}
	if err := f.TrashDelete(adminUser(), album); err != nil {
		t.Fatalf("TrashDelete: %v", err)
	}
	backdateTrashRecord(t, diskTrash, notes, 60*24*time.Hour)
	if n, err := f.TrashSweep(30 * 24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("TrashSweep = %d, %v; want one erased", n, err)
	}
	if left := mustTrashList(t, f); len(left) != 0 {
		t.Fatalf("trash after erase and sweep: %+v", left)
	}

	writeFile(t, root, "disk/again.txt", "x")
	if err := f.Remove(adminUser(), "/disk/again.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(adminUser(), "/home.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.TrashPurge(adminUser()); err != nil {
		t.Fatalf("TrashPurge: %v", err)
	}
	if left := mustTrashList(t, f); len(left) != 0 {
		t.Fatalf("trash after purge: %+v", left)
	}
	if reg := f.readRegistry(); len(reg.Mounts) != 1 {
		t.Fatalf("purge lost the registry: %+v", reg.Mounts)
	}
	writeFile(t, root, "disk/later.txt", "x")
	if err := f.Remove(adminUser(), "/disk/later.txt"); err != nil {
		t.Fatal(err)
	}
	if left := mustTrashList(t, f); len(left) != 1 {
		t.Fatalf("a delete after purge is not listed: %+v", left)
	}
}

// TestUnmountedDiskTrashIsSkipped: while a disk is away its items drop out
// of the list without breaking it, and come back when it returns.
func TestUnmountedDiskTrashIsSkipped(t *testing.T) {
	f, root := newMountedFS(t)
	if err := f.Remove(adminUser(), "/disk/notes.txt"); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(adminUser(), "/home.txt"); err != nil {
		t.Fatal(err)
	}
	away := filepath.Join(t.TempDir(), "unplugged")
	if err := os.Rename(filepath.Join(root, "disk"), away); err != nil {
		t.Fatal(err)
	}
	mkdirAll(t, root, "disk") // the empty mount point left behind
	if got := mustTrashList(t, f); len(got) != 1 {
		t.Fatalf("with the disk away: %+v, want only the root item", got)
	}
	if err := os.Remove(filepath.Join(root, "disk")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(away, filepath.Join(root, "disk")); err != nil {
		t.Fatal(err)
	}
	if got := mustTrashList(t, f); len(got) != 2 {
		t.Fatalf("with the disk back: %+v, want both items", got)
	}
}

// TestMountPointCannotBeDeletedOrMoved: the kernel refuses to rename a
// mount point, and a copy would carry off the whole disk.
func TestMountPointCannotBeDeletedOrMoved(t *testing.T) {
	f, root := newMountedFS(t)
	if err := f.Remove(adminUser(), "/disk"); !errors.Is(err, ErrMountPoint) {
		t.Fatalf("Remove(/disk) = %v, want ErrMountPoint", err)
	}
	if _, err := f.Rename(adminUser(), "/disk", "/", "disk2", false); !errors.Is(err, ErrMountPoint) {
		t.Fatalf("Rename(/disk) = %v, want ErrMountPoint", err)
	}
	if _, err := os.Stat(filepath.Join(root, "disk/notes.txt")); err != nil {
		t.Fatalf("the disk was disturbed: %v", err)
	}
}

// TestRegistryCannotPointOutside: the registry is only a hint. An entry
// that escapes the root, or a .trash that is a link, is ignored, so items
// planted elsewhere never surface.
func TestRegistryCannotPointOutside(t *testing.T) {
	needSymlinks(t)
	f, root := newMountedFS(t)
	outside := t.TempDir()
	writeFile(t, outside, "0123456789abcdef-planted.txt", "x")
	writeFile(t, outside, ".0123456789abcdef.json", `{"id":"0123456789abcdef","original_path":"/planted.txt"}`)
	mkdirAll(t, root, "evil")
	if err := os.Symlink(outside, filepath.Join(root, "evil", trashDirName)); err != nil {
		t.Fatal(err)
	}
	mkdirAll(t, root, trashDirName)
	writeFile(t, root, filepath.Join(trashDirName, trashRegistry), `{"mounts":["/evil","/../..","/disk/../.."]}`)

	if got := mustTrashList(t, f); len(got) != 0 {
		t.Fatalf("planted items surfaced: %+v", got)
	}
	if err := f.RestoreTrash(adminUser(), "0123456789abcdef-planted.txt"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("restore of a planted item = %v, want ErrNotExist", err)
	}
}
