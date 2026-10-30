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
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames src to dst, refusing with os.ErrExist when dst
// exists. renameat2's RENAME_NOREPLACE makes the check and the rename one
// atomic step, so two requests racing for one name cannot both win, and the
// loser's entry never replaces the winner's.
//
// A filesystem or kernel without the flag answers EINVAL (or ENOSYS); the
// portable check-then-rename takes over there.
func renameNoReplace(src, dst string) error {
	err := unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOSYS):
		return renameCheckFirst(src, dst)
	}
	return &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
}
