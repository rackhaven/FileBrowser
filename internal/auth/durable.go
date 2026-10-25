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
	"os"
	"path/filepath"
	"runtime"
)

// syncReplace is the write tail of every durable file: the temp file is
// pushed to the medium before its name changes, and the directory entry
// after, so a power cut can only ever leave the old file or the new one,
// never a zero-byte hybrid. WriteFile into a temp name followed by a
// bare rename is the trap both stores previously carried: rename is
// atomic for users, but a disk has its own ideas about when bytes land.
func syncReplace(tmp, target string) error {
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}
	if dir := filepath.Dir(target); dir != "" {
		if d, derr := os.Open(dir); derr == nil {
			if serr := d.Sync(); serr != nil && runtime.GOOS != "windows" {
				_ = d.Close()
				// Directory sync has no operating-system support on
				// Windows; the file sync above still bounds the worst
				// crash window to the rename itself.
				return serr
			}
			_ = d.Close()
		}
	}
	return nil
}
