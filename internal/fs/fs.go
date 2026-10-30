// Package fs maps virtual paths to real files on disk while enforcing the
// per-folder ACLs from the auth package.
//
// The security invariant this package exists to hold: no request, however
// crafted, may read or modify a byte outside Root. Every entry point resolves
// the requested virtual path through Resolve, which rejects traversal
// sequences and re-checks containment after following symlinks.

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
	iofs "io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// Errors callers are expected to translate into HTTP status codes.
var (
	// ErrForbidden means the ACL denied the operation.
	ErrForbidden = errors.New("fs: forbidden")
	// ErrNotExist means the path is outside the root, or does not exist.
	ErrNotExist = errors.New("fs: not found")
	// ErrNotDir means a directory was required.
	ErrNotDir = errors.New("fs: not a directory")
	// ErrReserved means the name collides with the temporary files the
	// uploader uses while an upload is still in flight.
	ErrReserved = errors.New("fs: name is reserved while uploads are in flight")
)

// uploadTempPrefix marks the temporary files the upload handler writes
// before renaming into place. Names with this prefix are hidden from
// listings and refused for new entries, so an in-flight upload can never be
// renamed, deleted or shadowed by another request.
const uploadTempPrefix = ".upload-"

// isUploadTempName reports whether name collides with in-flight uploads.
func isUploadTempName(name string) bool {
	return strings.HasPrefix(name, uploadTempPrefix)
}

// FS is a rooted view of the filesystem with ACL enforcement.
type FS struct {
	// root is the configured root as given, used for building paths.
	root string
	// realRoot is root with symlinks resolved, used for containment checks.
	// Comparing against this means a symlinked root does not break checks.
	realRoot string
	// thumbCache is the directory generated previews are stored in, or ""
	// when no cache is configured ( Thumbnail still works, just slower).
	thumbCache string
	// trashMu serialises updates to the registry of mount trashes.
	trashMu sync.Mutex
}

// New creates an FS rooted at dir. The directory is created if missing.
func New(dir string) (*FS, error) {
	if dir == "" {
		return nil, errors.New("fs: root must not be empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("fs: abs %s: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("fs: create root %s: %w", abs, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("fs: resolve root %s: %w", abs, err)
	}
	return &FS{root: abs, realRoot: real}, nil
}

// Root returns the resolved root directory.
func (f *FS) Root() string { return f.realRoot }

// Clean normalises a client-supplied virtual path to an absolute slash path
// with no trailing slash. It is purely lexical: "..", "." and duplicate slashes
// are collapsed by path.Clean, which is what makes Resolve's containment check
// sound.
func Clean(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	if p == "/" {
		return "/"
	}
	return strings.TrimSuffix(p, "/")
}

// Join appends a single child name to a virtual directory path, refusing
// anything that is not a plain name. This is the safe way to turn a
// user-supplied filename into a path.
func Join(dir, name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", ErrForbidden
	}
	if strings.ContainsRune(name, 0) {
		return "", ErrForbidden
	}
	// Without this branch the root would produce "//docs", which is a
	// different path for ACL matching and silently hides root-level entries.
	base := Clean(dir)
	if base == "/" {
		return "/" + name, nil
	}
	return base + "/" + name, nil
}

// Resolve maps a virtual path to a real path on disk.
//
// need is the minimum ACL level required. When need is AccessRead the user
// must be able to read the path itself; for listings use ResolveForList, which
// additionally accepts paths the user can only reach grants beneath.
//
// It returns ErrNotExist for anything that escapes the root (traversal, an
// absolute path, a symlink pointing outside) so callers do not leak the
// difference between "denied" and "missing".
func (f *FS) Resolve(u *auth.User, vpath string, need auth.AccessLevel) (string, error) {
	real, _, err := f.resolveVP(u, vpath, need)
	return real, err
}

// resolveVP is Resolve that also reports realVP, the virtual path of where
// the entry really lives once symlinks are followed.
//
// A symlink is followed only as far as the user could have walked on their
// own: the place it lands needs the same level as the path that named it.
// Without this, any link inside a readable folder would lend its reader
// whatever the link points at. A refusal there answers ErrNotExist, the same
// as a link pointing out of the root, because listings hide such links too.
func (f *FS) resolveVP(u *auth.User, vpath string, need auth.AccessLevel) (real, realVP string, err error) {
	vp := Clean(vpath)
	if !f.allowed(u, vp, need) {
		return "", "", ErrForbidden
	}
	real, realVP, err = f.locate(vp)
	if err != nil {
		return "", "", err
	}
	if realVP != vp && !f.allowed(u, realVP, need) {
		return "", "", ErrNotExist
	}
	return real, realVP, nil
}

// resolveEntry is resolveVP for operations on an entry itself rather than on
// what it points to (delete, move, replace). The final component is not
// followed: a symlink is judged where it sits, since the operation moves the
// link and never touches its target. Containment of the full path is still
// proven, so an entry that escapes the root stays unreachable.
func (f *FS) resolveEntry(u *auth.User, vpath string, need auth.AccessLevel) (real, realVP string, err error) {
	vp := Clean(vpath)
	if vp == "/" {
		return f.resolveVP(u, vp, need)
	}
	if !f.allowed(u, vp, need) {
		return "", "", ErrForbidden
	}
	if _, _, err := f.locate(vp); err != nil {
		return "", "", err
	}
	parentReal, parentRealVP, err := f.locate(parentDir(vp))
	if err != nil {
		return "", "", err
	}
	name := path.Base(vp)
	realVP, err = Join(parentRealVP, name)
	if err != nil {
		return "", "", err
	}
	if realVP != vp && !f.allowed(u, realVP, need) {
		return "", "", ErrNotExist
	}
	return filepath.Join(parentReal, name), realVP, nil
}

// locate maps a cleaned virtual path to disk and proves it stays inside the
// root, without consulting any ACL. It returns the unresolved real path
// (operating on the original path keeps os.Create/truncate semantics
// predictable) and the virtual path of where it resolves to.
func (f *FS) locate(vp string) (real, realVP string, err error) {
	if vp == "/" {
		return f.realRoot, "/", nil
	}
	real = filepath.Join(f.realRoot, filepath.FromSlash(strings.TrimPrefix(vp, "/")))
	if !within(f.realRoot, real) {
		return "", "", ErrNotExist
	}

	// The lexical check above is not enough: a symlink inside the root can
	// still point outside it. Resolve as much of the path as exists and
	// re-check containment afterwards.
	resolved, err := resolveExisting(real)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", "", ErrNotExist
		}
		return "", "", err
	}
	realVP, ok := f.virtualOf(resolved)
	if !ok {
		return "", "", ErrNotExist
	}
	return real, realVP, nil
}

// virtualOf expresses a resolved real path as a virtual one; ok is false
// when it lies outside the root.
func (f *FS) virtualOf(resolved string) (string, bool) {
	if !within(f.realRoot, resolved) {
		return "", false
	}
	rel, err := filepath.Rel(f.realRoot, resolved)
	if err != nil {
		return "", false
	}
	return Clean(filepath.ToSlash(rel)), true
}

// levelAt is the user's level on an entry named vp whose real location is
// realVP: the weaker of the two, so a symlink never lends more access than
// its target already grants.
func levelAt(u *auth.User, vp, realVP string) auth.AccessLevel {
	level := u.EffectiveLevel(vp)
	if realVP != vp {
		if target := u.EffectiveLevel(realVP); target < level {
			level = target
		}
	}
	return level
}

// passable reports whether a folder the user cannot read still leads to
// something they can, under both of its names.
func passable(u *auth.User, vp, realVP string) bool {
	return u.HasAnyGrantUnder(vp) && (realVP == vp || u.HasAnyGrantUnder(realVP))
}

// Level is the user's level on vpath, symlinks taken into account; AccessNone
// when the path cannot be located. The listing handler uses it to decide
// whether to offer uploads into a folder.
func (f *FS) Level(u *auth.User, vpath string) auth.AccessLevel {
	vp := Clean(vpath)
	_, realVP, err := f.locate(vp)
	if err != nil {
		return auth.AccessNone
	}
	return levelAt(u, vp, realVP)
}

// allowed applies the ACL. Admins bypass it entirely.
func (f *FS) allowed(u *auth.User, vpath string, need auth.AccessLevel) bool {
	if u == nil {
		return false
	}
	if u.Disabled {
		return false
	}
	if u.Admin {
		return true
	}
	return u.EffectiveLevel(vpath) >= need
}

// ResolveForList is Resolve with the relaxed rule used for directory listings,
// so a user granted only /photos/private can still open /photos and see it.
func (f *FS) ResolveForList(u *auth.User, vpath string) (string, error) {
	real, _, err := f.resolveForListVP(u, vpath)
	return real, err
}

// resolveForListVP is ResolveForList that also reports the folder's real
// virtual location, so walkers can judge the entries beneath it by where
// they really live.
//
// A folder the user cannot read but holds grants beneath is still opened,
// for traversal only: callers filter what comes back entry by entry. Both
// the named path and the real location must qualify, the same rule
// resolveVP applies to links.
func (f *FS) resolveForListVP(u *auth.User, vpath string) (real, realVP string, err error) {
	vp := Clean(vpath)
	if u == nil || u.Disabled || !u.HasAnyGrantUnder(vp) {
		return "", "", ErrForbidden
	}
	real, realVP, err = f.locate(vp)
	if err != nil {
		return "", "", err
	}
	if levelAt(u, vp, realVP) >= auth.AccessRead || passable(u, vp, realVP) {
		return real, realVP, nil
	}
	return "", "", ErrNotExist
}

// Entry is one item in a directory listing.
type Entry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	Mode    string    `json:"mode"`
	// Access is the level the requesting user holds on this entry, used by
	// the UI to decide which actions to offer.
	Access string `json:"access"`
	// Partial marks a directory the user cannot itself read but which leads
	// to something they can. Without it these folders would be unreachable.
	Partial bool `json:"partial,omitempty"`
}

// List returns the entries of a directory that the user is allowed to see.
//
// Entries the user has no access to are omitted entirely rather than shown as
// locked, because listing a name is itself a small information leak. Symlinks
// that resolve outside the root are omitted too, so every entry returned is
// genuinely openable.
func (f *FS) List(u *auth.User, vpath string) ([]Entry, error) {
	dir, dirRealVP, err := f.resolveForListVP(u, vpath)
	if err != nil {
		return nil, err
	}

	des, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotExist
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, ErrForbidden
		}
		return nil, err
	}

	entries := make([]Entry, 0, len(des))
	for _, de := range des {
		name := de.Name()

		// Temporary upload files are not listings material: they exist for
		// the seconds between the upload body arriving and the rename into
		// place, and another viewer shouldn't see (or race) them. The trash
		// is reserved for the same reason: it is machinery, not content.
		if isReservedName(name) {
			continue
		}

		child, err := Join(vpath, name)
		if err != nil {
			continue // defensive: a name we cannot address is not listable
		}

		info, ierr := de.Info()
		if ierr != nil {
			continue // vanished between ReadDir and Info
		}

		childReal, _ := Join(dirRealVP, name)
		// A symlink is the one entry type whose target can leave the root, so
		// it has to be proven safe before it is advertised. Resolve does the
		// same check on download; doing it here means the listing never
		// contains a row that would 404 when tapped.
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, rerr := resolveExisting(filepath.Join(dir, name))
			if rerr != nil {
				continue // dangling: hide it
			}
			rv, ok := f.virtualOf(resolved)
			if !ok {
				continue // points outside: hide it
			}
			childReal = rv
			// Stat the target so a symlinked folder is shown as a folder.
			if target, terr := os.Stat(resolved); terr == nil {
				info = target
			}
		}

		level := levelAt(u, child, childReal)
		partial := false
		if level == auth.AccessNone && info.IsDir() && passable(u, child, childReal) {
			partial = true
		}
		if level == auth.AccessNone && !partial {
			continue
		}

		entries = append(entries, Entry{
			Name:    name,
			Path:    child,
			IsDir:   info.IsDir(),
			Access:  level.String(),
			Partial: partial,
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Mode:    info.Mode().String(),
		})
	}

	// Folders first, then case-insensitive by name: predictable on both
	// Android and iOS file pickers.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		li, lj := strings.ToLower(entries[i].Name), strings.ToLower(entries[j].Name)
		if li != lj {
			return li < lj
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// Info describes a single file, enforcing at least read access.
func (f *FS) Info(u *auth.User, vpath string) (Entry, error) {
	vp := Clean(vpath)
	real, realVP, err := f.resolveVP(u, vp, auth.AccessRead)
	if err != nil {
		return Entry{}, err
	}
	info, err := os.Stat(real)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Entry{}, ErrNotExist
		}
		if errors.Is(err, os.ErrPermission) {
			return Entry{}, ErrForbidden
		}
		return Entry{}, err
	}

	return Entry{
		Name:    filepath.Base(real),
		Path:    vp,
		IsDir:   info.IsDir(),
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Mode:    info.Mode().String(),
		Access:  levelAt(u, vp, realVP).String(),
	}, nil
}

// Open returns an open file handle for streaming, enforcing read access.
func (f *FS) Open(u *auth.User, vpath string) (*os.File, os.FileInfo, error) {
	vp := Clean(vpath)
	if _, err := f.Resolve(u, vp, auth.AccessRead); err != nil {
		return nil, nil, err
	}
	// The open itself re-walks the path through the kernel's openat2 with the
	// root as its clamp, so the symlink race the Resolve re-check closes
	// above is also closed at the byte level.
	file, err := openInside(f.realRoot, relFromVP(vp), os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, ErrNotExist
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, nil, ErrForbidden
		}
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if info.IsDir() {
		file.Close()
		return nil, nil, ErrNotDir
	}
	return file, info, nil
}

// relFromVP expresses a virtual path relative to the root, in the slash form
// the openat2 family wants: "/docs/a.txt" becomes "docs/a.txt", the root
// itself becomes ".".
func relFromVP(vp string) string {
	if vp == "/" || vp == "" {
		return "."
	}
	return strings.TrimPrefix(vp, "/")
}

// within reports whether p is root itself or lies beneath it. filepath.Rel is
// used rather than a string prefix so "/srv/files-other" is not considered to
// be inside "/srv/files".
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// resolveExisting resolves symlinks in the deepest existing ancestor of p and
// re-appends the remaining segments. This lets us validate a path that is about
// to be created, where only the parent exists.
func resolveExisting(p string) (string, error) {
	current := p
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err // hit the filesystem root without finding anything
		}
		tail = append(tail, filepath.Base(current))
		current = parent
	}
}

// SweepUploadTemps erases abandoned upload and copy temporaries. Names
// with the .upload- prefix appear mid-routine in the destination folder
// and are renamed or removed by their creator when it finishes; the
// only temporaries of that shape left behind are the ones a crashed
// request never got to clean up. They are hidden from listings but not
// from the disk, so a crash per upload would gather them fast. One
// older than maxAge belongs to no live stream: the sweep keeps whatever
// a running upload could still be writing and lets the rest go.
func (f *FS) SweepUploadTemps(maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	if f.realRoot == "" {
		return 0, nil
	}

	// Collect first, remove after: WalkDir does not enjoy a directory
	// disappearing between reading the parent and reading the child, and
	// the pass runs often enough to not care about the second walk.
	cutoff := time.Now().UTC().Add(-maxAge)
	removed := 0
	var condemned []string
	werr := filepath.WalkDir(f.realRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if p != f.realRoot {
				return iofs.SkipDir // unreadable corner: leave it for tomorrow
			}
			return err
		}
		if !isUploadTempName(d.Name()) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.ModTime().UTC().After(cutoff) {
			return nil // vanished mid-walk, or young enough to keep
		}
		condemned = append(condemned, p)
		if d.IsDir() {
			return iofs.SkipDir
		}
		return nil
	})
	if werr != nil {
		return removed, werr
	}
	for _, p := range condemned {
		if err := os.RemoveAll(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
