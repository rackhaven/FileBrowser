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
	"archive/zip"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// Zip streams the contents of a directory into w as a zip archive, applying
// the same visibility rules as List: an entry is included when the user can
// read it, and folders the user can only pass through are entered rather than
// included as content.
//
// The archive always contains one top-level directory named after the folder
// (or "files" for the root), so an extraction lands in its own directory
// instead of spraying one folder's contents across the destination.
//
// Two entry types are deliberately skipped: in-flight upload temporaries, for
// the same reason listings hide them, and every symlink, because a symlinked
// file's content would be read through the link and the containment argument
// is weaker there than for real files. A symlink inside the root is a listing
// row that already passed Resolve-style verification; for a bulk archive the
// conservative choice costs nothing.
//
// The archive is written incrementally, so a folder of videos streams with
// constant memory; total size is not known in advance and the caller must not
// set Content-Length.
func (f *FS) Zip(u *auth.User, vpath string, w io.Writer) error {
	vp := Clean(vpath)
	startDir, err := f.ResolveForList(u, vp)
	if err != nil {
		return err
	}
	startName := zipName(vp)

	zw := zip.NewWriter(w)
	stop := func(err error) error {
		if cerr := zw.Close(); err == nil { // return the first failure
			return cerr
		}
		return err
	}

	var walk func(realDir, vDir string, isTop bool) error
	walk = func(realDir, vDir string, isTop bool) error {
		des, err := os.ReadDir(realDir)
		if err != nil {
			if errors.Is(err, syscall.ENOTDIR) {
				// The top being a file is a caller mistake worth reporting;
				// deeper down it just means an entry raced away.
				if isTop {
					return ErrNotDir
				}
				return nil
			}
			// A folder the OS itself won't show us is simply absent from
			// the archive; the ACL layer above already decided visibility.
			return nil
		}
		for _, de := range des {
			name := de.Name()

			if isReservedName(name) {
				continue
			}
			childVP, jerr := Join(vDir, name)
			if jerr != nil {
				continue // defensive: a name we cannot address is not listable
			}
			info, ierr := de.Info()
			if ierr != nil {
				continue // vanished between ReadDir and Info
			}

			if info.Mode()&os.ModeSymlink != 0 {
				// Verify like List does, then ignore the symlink either way:
				// its content is read through the link, which we do not do.
				resolved, rerr := resolveExisting(filepath.Join(realDir, name))
				if rerr != nil || !within(f.realRoot, resolved) {
					continue
				}
				if target, terr := os.Stat(resolved); terr == nil {
					info = target
				} else {
					continue
				}
			}

			// Mirror List's visibility: files need read; folders the user can
			// only pass through (partial) are entered for what lies beneath.
			level := u.EffectiveLevel(childVP)
			readable := level >= auth.AccessRead
			partial := !readable && info.IsDir() && u.HasAnyGrantUnder(childVP)
			if !readable && !partial {
				continue
			}

			rel := startName + "/" + relUnder(vpath, childVP)

			if info.IsDir() {
				if werr := walk(filepath.Join(realDir, name), childVP, false); werr != nil {
					return werr
				}
				continue
			}
			if !readable || !info.Mode().IsRegular() {
				// Unreachable folders are traversed above; files need read,
				// and anything unusual (fifo, device) is not archive material.
				continue
			}

			hdr := &zip.FileHeader{
				Name:     rel,
				Modified: info.ModTime(),
				Method:   zip.Deflate,
			}
			entry, err := zw.CreateHeader(hdr)
			if err != nil {
				return err
			}
			// The open goes through openat2 under the FS root, not a plain
			// path open: a raced symlink may not walk out of the root. The
			// relative path is derived from the real element, so an in-root
			// symlink target keeps working like before.
			target := filepath.Join(realDir, name)
			relTo, rerr := filepath.Rel(f.realRoot, target)
			if rerr != nil {
				continue // sits outside the root: not archive material
			}
			file, err := openInside(f.realRoot, filepath.ToSlash(relTo), os.O_RDONLY, 0)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
					continue // raced away, or unreadable now
				}
				return err
			}
			_, err = io.Copy(entry, file)
			ferr := file.Close()
			if err == nil {
				err = ferr
			}
			if err != nil {
				return err
			}
		}
		return nil
	}

	if werr := walk(startDir, Clean(vpath), true); werr != nil {
		return stop(werr)
	}
	return zw.Close()
}

// ZipInfo validates the folder for a zip download and returns the archive's
// top-level name, so the server can set headers before streaming. Zip
// afterwards repeats the check, which is cheap and keeps the archive name and
// content from drifting apart.
func (f *FS) ZipInfo(u *auth.User, vpath string) (string, error) {
	vp := Clean(vpath)
	dir, err := f.ResolveForList(u, vp)
	if err != nil {
		return "", err
	}
	// Resolve tolerates paths that do not exist yet (that is how creation
	// flows use it), but for an archive a missing folder is a client error
	// and must reach the handler before any body byte is written.
	if _, err := os.ReadDir(dir); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return "", ErrNotExist
		case errors.Is(err, syscall.ENOTDIR):
			return "", ErrNotDir
		case errors.Is(err, os.ErrPermission):
			return "", ErrForbidden
		default:
			return "", err
		}
	}
	return zipName(vp), nil
}

// zipName is the archive's single top-level directory name ("files" for the
// root, since it has a name meant for the machine, not for a person).
func zipName(vp string) string {
	if vp == "/" {
		return "files"
	}
	if name := path.Base(vp); name != "" && name != "." {
		return name
	}
	return "files"
}

// relUnder is the archive path of childVP beneath the zipped folder,
// excluding the top-level name itself (the caller writes that prefix).
func relUnder(vp, childVP string) string {
	rel := strings.TrimPrefix(childVP, vp)
	rel = strings.TrimPrefix(rel, "/")
	return rel
}
