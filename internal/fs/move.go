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
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// errMoveLeftovers reports a cross-filesystem move whose copy is complete
// but whose source could not be fully removed afterwards. Nothing is lost:
// the destination holds everything, and what remains at the source is a
// duplicate. Callers must keep the destination (and any record of it).
var errMoveLeftovers = errors.New("fs: moved by copying, but some of the original could not be removed")

// rename is the no-replace rename every move goes through; a variable only
// so tests can play a filesystem boundary or a filesystem without support.
var rename = renameNoReplace

// moveNoClobber moves src to dst without ever replacing something already at
// dst, which answers os.ErrExist instead. Symlinks move as themselves.
//
// Within one filesystem it is a rename. Across filesystems (a disk mounted
// inside the root, say) a rename is impossible, so the entry is copied to
// dst in full, flushed, and only then removed from src: a failure part way
// removes the partial copy and leaves src exactly as it was.
func moveNoClobber(src, dst string) error {
	err := rename(src, dst)
	if err == nil || !isCrossDevice(err) {
		return err
	}
	if err := copyTree(src, dst); err != nil {
		if !errors.Is(err, os.ErrExist) {
			_ = os.RemoveAll(dst) // copyTree created it: drop the partial copy
		}
		return err
	}
	if err := os.RemoveAll(src); err != nil {
		return fmt.Errorf("%w: %v", errMoveLeftovers, err)
	}
	return nil
}

// moveReplacing is moveNoClobber for a move the caller confirmed may replace
// a file at dst. Across filesystems the copy lands under a reserved name
// beside dst first and is renamed over it only once complete, so dst is
// never half-written.
func moveReplacing(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil || !isCrossDevice(err) {
		return err
	}
	id, err := trashID()
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(dst), uploadTempPrefix+"move-"+id)
	if err := copyTree(src, tmp); err != nil {
		if !errors.Is(err, os.ErrExist) {
			_ = os.RemoveAll(tmp)
		}
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.RemoveAll(src); err != nil {
		return fmt.Errorf("%w: %v", errMoveLeftovers, err)
	}
	return nil
}

// PlaceUpload moves a finished upload from its temporary name in the
// destination folder to its real name. Without overwrite the name is
// claimed atomically where the platform allows: a file that appeared at
// target while the body streamed (a second upload of the same name, say)
// answers os.ErrExist and is never replaced. The check UploadTarget made
// when the request began is long stale by then.
func PlaceUpload(tmp, target string, overwrite bool) error {
	if !overwrite {
		return rename(tmp, target)
	}
	err := os.Rename(tmp, target)
	if err != nil && errors.Is(err, os.ErrExist) {
		// Some platforms will not rename over a file; remove first so
		// replacing works the same everywhere.
		if rerr := os.Remove(target); rerr == nil {
			err = os.Rename(tmp, target)
		}
	}
	return err
}

// copyTree reproduces src at dst, which must not exist: the first step
// creates it exclusively, so an occupied dst answers os.ErrExist and is
// never touched. Regular files keep their bytes, mode and mtime and are
// synced before returning, folders keep mode and mtime, and symlinks are
// recreated as links. Anything else (a fifo, a device, a socket) refuses
// the whole copy, because a move must not quietly lose part of what it
// carries.
func copyTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch mode := info.Mode(); {
	case mode&os.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(target, dst)

	case mode.IsRegular():
		return copyFileExclusive(src, dst, info)

	case mode.IsDir():
		// Created owner-writable so the children can be written, then
		// given the source's own mode once they are in.
		if err := os.Mkdir(dst, 0o700); err != nil {
			return err
		}
		des, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, de := range des {
			if err := copyTree(filepath.Join(src, de.Name()), filepath.Join(dst, de.Name())); err != nil {
				return err
			}
		}
		if err := os.Chmod(dst, mode.Perm()); err != nil {
			return err
		}
		return os.Chtimes(dst, info.ModTime(), info.ModTime())

	default:
		return fmt.Errorf("fs: cannot move %s across filesystems: %s is not a file, folder or link", filepath.Base(src), mode.Type())
	}
}

func copyFileExclusive(src, dst string, info os.FileInfo) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		// The source is removed right after: its bytes must be on the
		// medium first, or a power cut could lose both copies.
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

// renameCheckFirst is the portable no-replace rename: refuse when dst is
// occupied, otherwise rename. It is also the fallback on Linux filesystems
// whose rename takes no flags.
func renameCheckFirst(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: os.ErrExist}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(src, dst)
}
