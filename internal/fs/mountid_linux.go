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

import "golang.org/x/sys/unix"

// mountIDOf identifies the mount p lives on, without following a final
// symlink. Linux reports a mount id through statx, which tells two bind
// mounts of one disk apart: they share a device number, yet a rename
// between them fails all the same. Kernels before 5.8 lack the field and
// fall back to the device number, tagged so the two kinds of id can never
// be mistaken for each other.
func mountIDOf(p string) (uint64, bool) {
	var stx unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, p, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stx)
	if err == nil && stx.Mask&unix.STATX_MNT_ID != 0 {
		return stx.Mnt_id, true
	}
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return 0, false
	}
	return uint64(st.Dev) | 1<<63, true
}
