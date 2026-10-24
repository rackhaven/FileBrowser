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
	"path"
	"path/filepath"
	"strings"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// Mkdir creates a directory inside dir, which must be writable by the user.
func (f *FS) Mkdir(u *auth.User, dir, name string) (Entry, error) {
	vpath, err := Join(dir, name)
	if err != nil {
		return Entry{}, err
	}
	if isReservedName(name) {
		return Entry{}, ErrReserved
	}
	real, err := f.Resolve(u, dir, auth.AccessWrite)
	if err != nil {
		return Entry{}, err
	}

	target := filepath.Join(real, name)
	if !within(f.realRoot, resolveFor(target)) {
		return Entry{}, ErrForbidden
	}
	if err := os.Mkdir(target, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Entry{}, fmt.Errorf("fs: %s already exists", name)
		}
		return Entry{}, err
	}

	info, err := os.Stat(target)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Name:    name,
		Path:    vpath,
		IsDir:   true,
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Mode:    info.Mode().String(),
		Access:  u.EffectiveLevel(vpath).String(),
	}, nil
}

// UploadTarget validates a destination for an upload and returns the real path
// to stream into plus its virtual path. The destination need not exist yet,
// but its parent must exist and be writable.
func (f *FS) UploadTarget(u *auth.User, dir, name string) (real, vpath string, err error) {
	vpath, err = Join(dir, name)
	if err != nil {
		return "", "", err
	}
	if isReservedName(name) {
		return "", "", ErrReserved
	}
	realDir, err := f.Resolve(u, dir, auth.AccessWrite)
	if err != nil {
		return "", "", err
	}

	target := filepath.Join(realDir, name)
	if !within(f.realRoot, resolveFor(target)) {
		return "", "", ErrForbidden
	}
	if info, err := os.Lstat(target); err == nil && info.IsDir() {
		return "", "", fmt.Errorf("fs: %s is a directory", name)
	}
	return target, vpath, nil
}

// Remove deletes a file or (recursively) a directory: really, it moves the
// entry into the reserved .trash directory with a record of where it came
// from, so accidental deletes are undoable (see RestoreTrash). Write access
// on the entry itself is required.
func (f *FS) Remove(u *auth.User, vpath string) error {
	vp := Clean(vpath)
	if isReservedName(path.Base(vp)) {
		return ErrReserved
	}
	real, err := f.Resolve(u, vp, auth.AccessWrite)
	if err != nil {
		return err
	}
	if real == f.realRoot {
		return fmt.Errorf("fs: refusing to delete the root directory")
	}
	return f.moveToTrash(u, real, vp)
}

// Rename moves an entry. Write access is required on both the source and the
// destination directory so a read-only user cannot shuffle files they cannot
// even see.
func (f *FS) Rename(u *auth.User, from, toDir, newName string) (Entry, error) {
	fromVP := Clean(from)
	if isReservedName(path.Base(fromVP)) {
		return Entry{}, ErrReserved
	}
	if isReservedName(newName) {
		return Entry{}, ErrReserved
	}
	src, err := f.Resolve(u, fromVP, auth.AccessWrite)
	if err != nil {
		return Entry{}, err
	}
	if src == f.realRoot {
		return Entry{}, fmt.Errorf("fs: refusing to move the root directory")
	}

	dstVP, err := Join(toDir, newName)
	if err != nil {
		return Entry{}, err
	}
	dstDir, err := f.Resolve(u, toDir, auth.AccessWrite)
	if err != nil {
		return Entry{}, err
	}
	target := filepath.Join(dstDir, newName)
	if !within(f.realRoot, resolveFor(target)) {
		return Entry{}, ErrForbidden
	}

	if err := os.Rename(src, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Entry{}, fmt.Errorf("fs: %s already exists", newName)
		}
		return Entry{}, err
	}

	info, err := os.Stat(target)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Name:    newName,
		Path:    dstVP,
		IsDir:   info.IsDir(),
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Mode:    info.Mode().String(),
		Access:  u.EffectiveLevel(dstVP).String(),
	}, nil
}

// resolveFor returns the fully symlink-resolved form of p, falling back to p
// itself if it does not exist yet. Used for containment checks on paths that
// are about to be created.
func resolveFor(p string) string {
	resolved, err := resolveExisting(p)
	if err != nil {
		return p
	}
	return resolved
}

// Usage reports total bytes and file count under root, used by the dashboard.
type Usage struct {
	Files int64 `json:"files"`
	Dirs  int64 `json:"dirs"`
	Bytes int64 `json:"bytes"`
}

// Usage walks the tree the user can see and totals it. Errors on individual
// entries are skipped rather than aborting the walk.
func (f *FS) Usage(u *auth.User, vpath string, maxDepth int) (Usage, error) {
	root, err := f.ResolveForList(u, vpath)
	if err != nil {
		return Usage{}, err
	}

	var out Usage
	base := Clean(vpath)
	// bound the walk so a huge tree cannot pin the server
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// Deleted items live in the trash and reserved names are machinery,
		// not content: neither belongs in usage numbers.
		if isReservedName(d.Name()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		if rel == "." {
			return nil
		}
		if maxDepth > 0 && len(splitDepth(rel)) > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		child := childPath(base, rel)
		if !u.HasAnyGrantUnder(child) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			out.Dirs++
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		out.Files++
		out.Bytes += info.Size()
		return nil
	})
	return out, nil
}

func splitDepth(rel string) []string {
	return strings.Split(rel, string(filepath.Separator))
}

// childPath builds the virtual path of rel inside base.
//
// This is a lexical join, deliberately distinct from Join: rel here comes from
// filepath.Rel over a tree that was already proven to sit inside the root, and
// legitimately spans several segments. Join rejects slashes because it is fed
// untrusted single filenames. Passing a multi-segment path to Join would fail
// its validation and silently skip the entry.
func childPath(base, rel string) string {
	rel = strings.Trim(filepath.ToSlash(rel), "/")
	if rel == "" || rel == "." {
		return Clean(base)
	}
	return Clean(base + "/" + rel)
}

// Copy duplicates an entry: a file becomes an independent file with the same
// bytes, a folder becomes an independent subtree with the same shape. Write
// access on the destination directory and read on the source is required; the
// destination refuses to replace anything already sitting there, so copying
// never destroys someone else's work.
//
// The work happens under a reserved temporary name and is renamed into place
// only when it completes, so a copy that dies halfway leaves nothing behind
// and callers never see a half-written duplicate under its real name.
//
// Symlinks inside the tree are resolved and their content copied; a folder
// symlink is recorded but not followed deeply, so a link-loops layout cannot
// spin here. Unusual files (fifos, devices, sockets) are skipped.
func (f *FS) Copy(u *auth.User, from, toDir, name string) (Entry, error) {
	fromVP := Clean(from)
	if isReservedName(path.Base(fromVP)) {
		return Entry{}, ErrReserved
	}
	if name == "" {
		name = path.Base(fromVP)
	}
	if isReservedName(name) {
		return Entry{}, ErrReserved
	}

	srcReal, err := f.Resolve(u, fromVP, auth.AccessRead)
	if err != nil {
		return Entry{}, err
	}
	if srcReal == f.realRoot {
		return Entry{}, fmt.Errorf("fs: refusing to copy the root directory")
	}
	dstDirReal, err := f.Resolve(u, Clean(toDir), auth.AccessWrite)
	if err != nil {
		return Entry{}, err
	}

	dstVP, err := Join(toDir, name)
	if err != nil {
		return Entry{}, err
	}
	dst := filepath.Join(dstDirReal, name)
	if !within(f.realRoot, resolveFor(dst)) {
		return Entry{}, ErrForbidden
	}
	// A copy is a create, not a replace: an existing destination is refused
	// rather than overwritten. (A directory rename that lands on a non-empty
	// target fails in the kernel itself, so this window stays narrow.)
	if _, lerr := os.Lstat(dst); lerr == nil {
		return Entry{}, os.ErrExist
	}

	dstInfo, err := os.Lstat(srcReal)
	if err != nil {
		return Entry{}, err
	}
	// Both kinds stage under the reserved prefix, invisible to listings and
	// unreachable through the API, and both finalise with a rename.
	if dstInfo.IsDir() {
		tmp, merr := os.MkdirTemp(dstDirReal, uploadTempPrefix+"copy-")
		if merr != nil {
			return Entry{}, merr
		}
		if err := f.copyWalk(srcReal, tmp); err != nil {
			os.RemoveAll(tmp)
			return Entry{}, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.RemoveAll(tmp)
			return Entry{}, err
		}
	} else {
		rel, ok := relOfReal(f.realRoot, srcReal)
		if !ok {
			return Entry{}, ErrForbidden
		}
		file, aerr := os.CreateTemp(dstDirReal, uploadTempPrefix+"copy-*")
		if aerr != nil {
			return Entry{}, aerr
		}
		tmpName := file.Name()
		serr := f.copyFileInto(file, rel, dstInfo)
		cerr := file.Close()
		if err := errors.Join(serr, cerr); err != nil {
			os.Remove(tmpName)
			return Entry{}, err
		}
		if err := os.Rename(tmpName, dst); err != nil {
			os.Remove(tmpName)
			return Entry{}, err
		}
	}

	info, err := os.Lstat(dst)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Name:    name,
		Path:    dstVP,
		IsDir:   info.IsDir(),
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Mode:    info.Mode().String(),
		Access:  u.EffectiveLevel(dstVP).String(),
	}, nil
}

// relOfReal expresses a real path relative to the containment root, in slash
// form, for openInside; ok is false when the path is not under root.
func relOfReal(root, real string) (string, bool) {
	rel, err := filepath.Rel(root, real)
	if err != nil {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// copyFileInto streams a source file's bytes (by its slash path relative to
// the containment root) into an already-open destination file, keeping the
// source's regular mode bits. The open re-walks the path through openat2, so
// a raced symlink cannot reach outside while bytes move.
func (f *FS) copyFileInto(dst *os.File, rel string, info os.FileInfo) error {
	if rel == "" {
		return fmt.Errorf("fs: copy source escapes the root")
	}
	src, err := openInside(f.realRoot, rel, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return os.Chmod(dst.Name(), info.Mode()&0o777)
}

// copyWalk mirrors src into dst: same names, same regular-file bytes, dir
// modes carried over, reserved names and folder symlinks left out.
func (f *FS) copyWalk(srcDir, dstDir string) error {
	des, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, de := range des {
		name := de.Name()
		if isReservedName(name) {
			continue // machinery never duplicates
		}
		srcPath := filepath.Join(srcDir, name)
		dstPath := filepath.Join(dstDir, name)

		info, ierr := de.Info()
		if ierr != nil {
			continue // vanished mid-copy, like the zip walker
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, rerr := resolveExisting(srcPath)
			if rerr != nil || !within(f.realRoot, resolved) {
				continue // invisible to listings, invisible to copies
			}
			target, terr := os.Stat(resolved)
			if terr != nil {
				continue
			}
			if target.IsDir() {
				continue // do not climb through folder links: cycles
			}
			rel, rok := relOfReal(f.realRoot, resolved)
			if !rok {
				return ErrForbidden
			}
			out, aerr := os.CreateTemp(dstDir, uploadTempPrefix+"copy-*")
			if aerr != nil {
				return aerr
			}
			serr := f.copyFileInto(out, rel, target)
			cerr := out.Close()
			if err := errors.Join(serr, cerr); err != nil {
				os.Remove(out.Name())
				return err
			}
			if err := os.Rename(out.Name(), dstPath); err != nil {
				os.Remove(out.Name())
				return err
			}
			continue
		}
		if info.IsDir() {
			if err := os.MkdirAll(dstPath, info.Mode()&0o777); err != nil {
				return err
			}
			if err := f.copyWalk(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue // fifos, devices, sockets: not archive material
		}
		rel, rok := relOfReal(f.realRoot, srcPath)
		if !rok {
			return ErrForbidden
		}
		out, aerr := os.CreateTemp(dstDir, uploadTempPrefix+"copy-*")
		if aerr != nil {
			return aerr
		}
		serr := f.copyFileInto(out, rel, info)
		cerr := out.Close()
		if err := errors.Join(serr, cerr); err != nil {
			os.Remove(out.Name())
			return err
		}
		if err := os.Rename(out.Name(), dstPath); err != nil {
			os.Remove(out.Name())
			return err
		}
	}
	return nil
}
