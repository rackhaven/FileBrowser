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
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
)

// A disk mounted inside the root gets a trash of its own, at the top of
// the mount: deleting from it is then a rename, as it is everywhere else,
// rather than a copy of every byte onto the root's disk. The root's trash
// keeps a registry of these, so listing, restore and retention find them
// without walking the tree. A registered disk that is not mounted at the
// moment simply contributes nothing; its items reappear when it returns.

// mountID is how the trash tells mounts apart; a variable only so tests
// can lay out mounts without root privileges.
var mountID = mountIDOf

// trashRegistry names the file in the root trash that lists the virtual
// paths of mount tops holding a trash. The leading dot keeps it apart from
// items, as with records.
const trashRegistry = ".mounts.json"

type trashRegistryFile struct {
	Mounts []string `json:"mounts"`
}

// trashLoc is one trash directory: its real path, and the virtual path of
// the mount top it sits in ("/" for the root's own trash).
type trashLoc struct {
	dir string
	top string
}

// rootTrash is the root's trash location, whether or not it exists yet.
func (f *FS) rootTrash() trashLoc {
	return trashLoc{dir: filepath.Join(f.root, trashDirName), top: "/"}
}

// trashFor picks and creates the trash an entry at real is deleted into:
// the one at the top of the mount its folder lives on. Whenever that
// cannot be established or used (no mount ids on this platform, a
// read-only disk, a registry that will not save), it is the root's trash,
// and the move copies.
func (f *FS) trashFor(real string) (trashLoc, error) {
	if loc, ok := f.mountTrash(real); ok {
		return loc, nil
	}
	dir, err := f.trashDir()
	return trashLoc{dir: dir, top: "/"}, err
}

func (f *FS) mountTrash(real string) (trashLoc, bool) {
	parent := resolveFor(filepath.Dir(real))
	rootID, ok := mountID(f.realRoot)
	if !ok {
		return trashLoc{}, false
	}
	id, ok := mountID(parent)
	if !ok || id == rootID {
		return trashLoc{}, false
	}
	// Climb while the folder above is still inside the root and on the
	// same mount: where that stops is the mount's top.
	top := parent
	for {
		up := filepath.Dir(top)
		if up == top || !within(f.realRoot, up) {
			break
		}
		if upID, ok := mountID(up); !ok || upID != id {
			break
		}
		top = up
	}
	topVP, ok := f.virtualOf(top)
	if !ok || topVP == "/" {
		return trashLoc{}, false
	}
	dir := filepath.Join(top, trashDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return trashLoc{}, false
	}
	// Registered before first use: an item in an unregistered trash would
	// be invisible to everything that lists the trash.
	if err := f.registerTrash(topVP); err != nil {
		return trashLoc{}, false
	}
	return trashLoc{dir: dir, top: topVP}, true
}

// registerTrash adds a mount top to the registry if it is not there yet.
func (f *FS) registerTrash(topVP string) error {
	f.trashMu.Lock()
	defer f.trashMu.Unlock()
	reg := f.readRegistry()
	for _, m := range reg.Mounts {
		if m == topVP {
			return nil
		}
	}
	reg.Mounts = append(reg.Mounts, topVP)
	root, err := f.trashDir()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(root, ".mounts.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(root, trashRegistry))
}

func (f *FS) readRegistry() trashRegistryFile {
	var reg trashRegistryFile
	raw, err := os.ReadFile(filepath.Join(f.root, trashDirName, trashRegistry))
	if err == nil {
		_ = json.Unmarshal(raw, &reg) // unreadable: as if empty
	}
	return reg
}

// trashDirs lists every trash that exists right now: the root's first, then
// each registered mount's. A registered path is used only when it still
// resolves to itself inside the root and its trash is a real directory,
// never a link, so a stale or doctored registry cannot point anywhere else.
func (f *FS) trashDirs() []trashLoc {
	var out []trashLoc
	if isRealDir(f.rootTrash().dir) {
		out = append(out, f.rootTrash())
	}
	seen := map[string]bool{"/": true}
	for _, m := range f.readRegistry().Mounts {
		vp := Clean(m)
		if seen[vp] {
			continue
		}
		seen[vp] = true
		real, realVP, err := f.locate(vp)
		if err != nil || realVP != vp {
			continue
		}
		dir := filepath.Join(real, trashDirName)
		if isRealDir(dir) {
			out = append(out, trashLoc{dir: dir, top: vp})
		}
	}
	return out
}

func isRealDir(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.IsDir()
}

// findTrashItem locates a trashed item and its record by item name.
func (f *FS) findTrashItem(item string) (trashLoc, TrashMeta, bool) {
	id := trashIDOf(item)
	if id == "" {
		return trashLoc{}, TrashMeta{}, false
	}
	for _, loc := range f.trashDirs() {
		if _, err := os.Lstat(filepath.Join(loc.dir, item)); err != nil {
			continue
		}
		if meta, ok := f.readTrashMeta(loc.dir, id); ok {
			return loc, meta, true
		}
	}
	return trashLoc{}, TrashMeta{}, false
}

// trashPathOf is the virtual path an item in loc is shown under.
func trashPathOf(loc trashLoc, item string) string {
	return Clean(path.Join(loc.top, trashDirName, item))
}

// isMountPoint reports whether the entry at real is the top of a mount of
// its own. Such a folder cannot be renamed or deleted as a unit (the kernel
// refuses, and a copy would take the whole disk), so callers refuse first.
func (f *FS) isMountPoint(real string) bool {
	id, ok := mountID(real)
	if !ok {
		return false
	}
	parentID, ok := mountID(resolveFor(filepath.Dir(real)))
	return ok && id != parentID
}

// ErrMountPoint refuses deleting or moving a folder that is a mounted disk.
var ErrMountPoint = errors.New("fs: that folder is a mounted disk; delete or move what is inside it instead")
