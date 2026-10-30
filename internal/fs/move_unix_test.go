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

//go:build !windows

package fs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestCrossFilesystemMoveRefusesWhatItCannotCarry: a fifo cannot be
// copied, so the whole delete is refused and nothing changes on either
// side, rather than a move that quietly loses part of the folder.
func TestCrossFilesystemMoveRefusesWhatItCannotCarry(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "disk/box/a.txt", "a")
	if err := syscall.Mkfifo(filepath.Join(root, "disk/box/pipe"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pretendOtherFilesystem(t)

	if err := f.Remove(adminUser(), "/disk/box"); err == nil {
		t.Fatal("a move that cannot carry a fifo must fail")
	}
	if b, _ := os.ReadFile(filepath.Join(root, "disk/box/a.txt")); string(b) != "a" {
		t.Errorf("original disturbed: %q", b)
	}
	if left, _ := os.ReadDir(filepath.Join(root, trashDirName)); len(left) != 0 {
		t.Errorf("partial copy or record left in the trash: %d entries", len(left))
	}
}

// TestMoveNoClobberCrossesARealBoundary: the fallback is keyed on the
// kernel's own error, so prove it against a real one where the machine has
// two filesystems to hand (/dev/shm is its own tmpfs on most Linux hosts).
func TestMoveNoClobberCrossesARealBoundary(t *testing.T) {
	shm, err := os.MkdirTemp("/dev/shm", "fb-move-")
	if err != nil {
		t.Skipf("no /dev/shm: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(shm) })
	here := t.TempDir()

	probe := filepath.Join(shm, "probe")
	writeFile(t, shm, "probe", "x")
	if err := os.Rename(probe, filepath.Join(here, "probe")); err == nil || !isCrossDevice(err) {
		t.Skipf("/dev/shm and the temp dir share a filesystem here (rename: %v)", err)
	}

	writeFile(t, shm, "tree/sub/f.txt", "carried")
	if err := moveNoClobber(filepath.Join(shm, "tree"), filepath.Join(here, "tree")); err != nil {
		t.Fatalf("moveNoClobber across a real boundary: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(here, "tree/sub/f.txt")); string(b) != "carried" {
		t.Fatalf("moved content = %q", b)
	}
	if _, err := os.Lstat(filepath.Join(shm, "tree")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still present: %v", err)
	}
}
