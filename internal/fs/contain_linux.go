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
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Opening files through openat2 instead of a bare os.Open closes the last
// gap the resolve-and-recheck scheme can only narrow: the window between the
// recheck and the open, during which a racing writer can replace a component
// in the path with a symlink that points outside the root. The kernel does
// the path walk itself here, clamped to the root directory descriptor, so
// nothing outside the root can be reached at all.
//
// RESOLVE_NO_MAGICLINKS refuses /proc-style links, which never serve real
// content. RESOLVE_NO_XDEV is deliberately left out: a subdirectory mounted
// inside the root is a legitimate layout.

// dirAt opens root itself as a directory descriptor for relative opens.
func dirAt(root string) (int, error) {
	return unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
}

// fileAt opens rel (slash form, relative to dirFD) through dirFD. Every
// symlink on the way is resolved but clamped inside dirFD.
func fileAt(dirFD int, rel string, flags int, perm os.FileMode) (*os.File, error) {
	if rel == "" {
		rel = "."
	}
	fd, err := unix.Openat2(dirFD, rel, &unix.OpenHow{
		Flags:   uint64(unix.O_CLOEXEC | flags),
		Mode:    uint64(perm & os.ModePerm),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		// A resolution that would leave the root or hit a magic link is a
		// containment refusal; say so in the API's own vocabulary.
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.ENAMETOOLONG) {
			return nil, &os.PathError{Op: "open", Path: rel, Err: os.ErrPermission}
		}
		return nil, &os.PathError{Op: "open", Path: rel, Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join("/", rel)), nil
}

// openInside opens a slash path relative to root with kernel-enforced
// containment. flags take the plain os open flags.
func openInside(root, rel string, flags int, perm os.FileMode) (*os.File, error) {
	dirFD, err := dirAt(root)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	return fileAt(dirFD, rel, flags, perm)
}
