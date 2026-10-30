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

//go:build linux

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMountIDOfTellsMountsApart: the real kernel answer, not a stub. Two
// folders on one mount match; /dev/shm, where it is a mount of its own,
// differs, exactly when a rename between them would fail.
func TestMountIDOfTellsMountsApart(t *testing.T) {
	here := t.TempDir()
	mkdirAll(t, here, "sub")
	a, okA := mountIDOf(here)
	b, okB := mountIDOf(filepath.Join(here, "sub"))
	if !okA || !okB || a != b {
		t.Fatalf("one mount, two ids: %d/%v %d/%v", a, okA, b, okB)
	}

	shm, err := os.MkdirTemp("/dev/shm", "fb-mnt-")
	if err != nil {
		t.Skipf("no /dev/shm: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(shm) })
	writeFile(t, shm, "probe", "x")
	err = os.Rename(filepath.Join(shm, "probe"), filepath.Join(here, "probe"))
	if err == nil || !isCrossDevice(err) {
		t.Skip("/dev/shm is on the same mount here")
	}
	if c, ok := mountIDOf(shm); !ok || c == a {
		t.Fatalf("/dev/shm id %d/%v matches the temp dir's %d", c, ok, a)
	}
}
