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
	"syscall"
	"testing"
	"time"
)

// TestRenameNoReplaceRefusesOccupied: nothing already at the destination is
// ever replaced, an empty folder included (plain rename replaces those).
func TestRenameNoReplaceRefusesOccupied(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "new")
	writeFile(t, dir, "b.txt", "old")
	mkdirAll(t, dir, "src-dir/inner")
	mkdirAll(t, dir, "empty-dir")

	for _, c := range []struct{ src, dst string }{{"a.txt", "b.txt"}, {"src-dir", "empty-dir"}} {
		err := renameNoReplace(filepath.Join(dir, c.src), filepath.Join(dir, c.dst))
		if !errors.Is(err, os.ErrExist) {
			t.Errorf("rename %s onto %s = %v, want ErrExist", c.src, c.dst, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "b.txt")); string(b) != "old" {
		t.Errorf("destination file was replaced: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "src-dir/inner")); err != nil {
		t.Errorf("source folder disturbed: %v", err)
	}
	// The portable fallback keeps the same promise.
	if err := renameCheckFirst(filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")); !errors.Is(err, os.ErrExist) {
		t.Errorf("renameCheckFirst onto a file = %v, want ErrExist", err)
	}
	if err := renameNoReplace(filepath.Join(dir, "a.txt"), filepath.Join(dir, "c.txt")); err != nil {
		t.Errorf("rename to a free name: %v", err)
	}
}

// pretendOtherFilesystem makes every rename fail the way a move between
// two mounts does, for the duration of the test.
func pretendOtherFilesystem(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("cross-device errors are spelled differently on Windows")
	}
	old := rename
	rename = func(src, dst string) error {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: syscall.EXDEV}
	}
	t.Cleanup(func() { rename = old })
}

// TestDeleteAndRestoreAcrossFilesystems: a folder on a disk mounted inside
// the root goes to the trash and comes back whole, though no rename can
// cross the boundary. Bytes, modes, times and links all survive the trip.
func TestDeleteAndRestoreAcrossFilesystems(t *testing.T) {
	needSymlinks(t)
	root := t.TempDir()
	writeFile(t, root, "disk/album/a.jpg", "photo")
	writeFile(t, root, "disk/album/deep/b.txt", "note")
	if err := os.Chmod(filepath.Join(root, "disk/album/deep/b.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.jpg", filepath.Join(root, "disk/album/link")); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(root, "disk/album/a.jpg"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pretendOtherFilesystem(t)

	if err := f.Remove(adminUser(), "/disk/album"); err != nil {
		t.Fatalf("delete across filesystems: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "disk/album")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original still present after delete: %v", err)
	}
	if err := f.RestoreTrash(adminUser(), trashItem(t, f).Name); err != nil {
		t.Fatalf("restore across filesystems: %v", err)
	}

	album := filepath.Join(root, "disk/album")
	if b, _ := os.ReadFile(filepath.Join(album, "deep/b.txt")); string(b) != "note" {
		t.Errorf("deep file content = %q", b)
	}
	if info, err := os.Stat(filepath.Join(album, "deep/b.txt")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("deep file mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	if info, err := os.Stat(filepath.Join(album, "a.jpg")); err != nil || !info.ModTime().Equal(stamp) {
		t.Errorf("mtime not kept: %v, %v", info.ModTime(), err)
	}
	if target, err := os.Readlink(filepath.Join(album, "link")); err != nil || target != "a.jpg" {
		t.Errorf("link = %q, %v; want it recreated as a link to a.jpg", target, err)
	}
	if left, _ := os.ReadDir(filepath.Join(root, trashDirName)); len(left) != 0 {
		t.Errorf("trash not empty after restore: %d entries", len(left))
	}
}

// TestMoveAcrossFilesystems: moving between mounts works too, with and
// without replacing a file at the destination.
func TestMoveAcrossFilesystems(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "disk/a.txt", "a")
	writeFile(t, root, "disk/b.txt", "b")
	writeFile(t, root, "other/b.txt", "stale")
	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pretendOtherFilesystem(t)

	if _, err := f.Rename(adminUser(), "/disk/a.txt", "/other", "a.txt", false); err != nil {
		t.Fatalf("move: %v", err)
	}
	if _, err := f.Rename(adminUser(), "/disk/b.txt", "/other", "b.txt", false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("move onto a file without overwrite = %v, want ErrExist", err)
	}
	if _, err := f.Rename(adminUser(), "/disk/b.txt", "/other", "b.txt", true); err != nil {
		t.Fatalf("move with overwrite: %v", err)
	}
	for name, want := range map[string]string{"other/a.txt": "a", "other/b.txt": "b"} {
		if b, _ := os.ReadFile(filepath.Join(root, name)); string(b) != want {
			t.Errorf("%s = %q, want %q", name, b, want)
		}
	}
	if left, _ := os.ReadDir(filepath.Join(root, "disk")); len(left) != 0 {
		t.Errorf("sources left behind: %d entries", len(left))
	}
}

// TestPlaceUploadNeverReplacesWithoutOverwrite: a file that appeared while
// an upload streamed survives it; with overwrite, it is replaced.
func TestPlaceUploadNeverReplacesWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".upload-1", "late upload")
	writeFile(t, dir, "report.pdf", "arrived first")

	if err := PlaceUpload(filepath.Join(dir, ".upload-1"), filepath.Join(dir, "report.pdf"), false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("PlaceUpload without overwrite = %v, want ErrExist", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "report.pdf")); string(b) != "arrived first" {
		t.Fatalf("existing file replaced: %q", b)
	}
	if err := PlaceUpload(filepath.Join(dir, ".upload-1"), filepath.Join(dir, "report.pdf"), true); err != nil {
		t.Fatalf("PlaceUpload with overwrite: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "report.pdf")); string(b) != "late upload" {
		t.Fatalf("overwrite did not replace: %q", b)
	}
}
