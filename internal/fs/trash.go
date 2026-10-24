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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// trashDirName is the one reserved directory name. Deletes move entries
// here rather than unlinking them, so a slip of the finger is undoable.
const trashDirName = ".trash"

// isReservedName reports whether name cannot be created or addressed by
// users: in-flight upload temporaries keep the .upload- prefix, and the
// trash keeps .trash.
func isReservedName(name string) bool {
	return isUploadTempName(name) || name == trashDirName
}

// TrashMeta is the sidecar record for one trashed entry. It is what makes
// restore possible after a restart, because a rename carries no origin.
type TrashMeta struct {
	ID           string    `json:"id"`
	OriginalPath string    `json:"original_path"`
	By           string    `json:"by"`
	DeletedAt    time.Time `json:"deleted_at"`
}

// TrashEntry is one item in the trash, as the interface sees it.
type TrashEntry struct {
	Name         string    `json:"name"`
	OriginalPath string    `json:"original_path"`
	TrashPath    string    `json:"trash_path"`
	IsDir        bool      `json:"is_dir"`
	Size         int64     `json:"size"`
	DeletedAt    time.Time `json:"deleted_at"`
	DeletedBy    string    `json:"deleted_by"`
	CanRestore   bool      `json:"can_restore"`
}

// trashIDLen is the fixed width of a trash id in hex characters.
const trashIDLen = 16

// trashID returns trashIDLen hex characters of randomness. Items are named
// <id>-<originalName> and records are .<id>.json.
func trashID() (string, error) {
	var b [trashIDLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("fs: trash id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// trashDir creates the trash directory on first use and returns its path.
// 0700: users go through the ACL layer for anything in it, never the
// directory itself.
func (f *FS) trashDir() (string, error) {
	dir := filepath.Join(f.root, trashDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("fs: create trash: %w", err)
	}
	return dir, nil
}

// moveToTrash assumes the caller holds the resolved source path (real) the
// user is entitled to delete. It moves the entry into the trash and writes
// the sidecar record that remembers where it came from.
//
// Two different moves are used, because neither claim is correct for both:
//   - files: a hard link claims the trash name atomically (link refuses to
//     replace, which detects an id collision), then the original is unlinked.
//   - folders: rename is the only option, and rename of a dir onto an
//     existing name fails except when that name is an empty directory. An
//     id collision is recovered by drawing a fresh id; a drained empty dir
//     could in principle be replaced, which is harmless (it held nothing).
//
// Symlinks move as themselves both ways: the trash never follows them.
func (f *FS) moveToTrash(u *auth.User, real, vp string) error {
	info, err := os.Lstat(real)
	if err != nil {
		return err
	}
	trash, err := f.trashDir()
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		id, ierr := trashID()
		if ierr != nil {
			return ierr
		}
		meta := TrashMeta{
			ID:           id,
			OriginalPath: vp,
			By:           u.Username,
			DeletedAt:    time.Now().UTC(),
		}
		metaPath := filepath.Join(trash, "."+id+".json")
		itemName := id + "-" + info.Name()
		itemPath := filepath.Join(trash, itemName)

		// The record is written first: a move without a record would
		// strand an unrestoreable entry. A failed move removes its record.
		raw, merr := json.MarshalIndent(meta, "", "  ")
		if merr != nil {
			return merr
		}
		if err := os.WriteFile(metaPath, raw, 0o600); err != nil {
			return fmt.Errorf("fs: trash record: %w", err)
		}

		if info.IsDir() {
			lastErr = os.Rename(real, itemPath)
		} else {
			lastErr = os.Link(real, itemPath)
		}
		if lastErr != nil {
			_ = os.Remove(metaPath)
			continue // a collision or a hiccup: fresh id, try again
		}
		if !info.IsDir() {
			// The link already copied the content safely under a protected
			// name; unlinking the original completes the move.
			if rerr := os.Remove(real); rerr != nil {
				// Keep both copies rather than lose data, and surface the
				// failure so the caller knows the delete did not actually
				// finish.
				_ = os.Remove(itemPath)
				_ = os.Remove(metaPath)
				return rerr
			}
		}
		return nil
	}
	return lastErr
}

// TrashList returns the entries the caller may act on. An admin sees
// everything; anyone else sees an entry only when they still have write
// access to the place it came from, because restore is going to move a
// thing they cannot own back into a tree they cannot write.
func (f *FS) TrashList(u *auth.User) ([]TrashEntry, error) {
	if u == nil || u.Disabled {
		return nil, ErrForbidden
	}
	trash, err := f.trashDir()
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(trash)
	if err != nil {
		return nil, err
	}

	admin := u.Admin
	out := make([]TrashEntry, 0, len(des)/2)
	for _, de := range des {
		name := de.Name()
		if name != "" && name[0] == '.' {
			continue // sidecar records never surface as items
		}
		id := trashIDOf(name)
		if id == "" {
			continue // an item with no recoverable record is a parking lot
		}
		meta, ok := f.readTrashMeta(trash, id)
		if !ok {
			continue
		}
		entry, ok := trashEntryFor(de, trash, name, meta)
		if !ok {
			continue
		}
		entry.CanRestore = admin || canRestore(u, meta.OriginalPath)
		if !admin && !entry.CanRestore {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

func trashEntryFor(de os.DirEntry, trash, name string, meta TrashMeta) (TrashEntry, bool) {
	info, err := de.Info()
	if err != nil {
		return TrashEntry{}, false
	}
	return TrashEntry{
		Name:         name,
		OriginalPath: meta.OriginalPath,
		TrashPath:    Clean("/" + trashDirName + "/" + name),
		IsDir:        info.IsDir(),
		Size:         info.Size(),
		DeletedAt:    meta.DeletedAt,
		DeletedBy:    meta.By,
	}, true
}

// canRestore reports whether the user may move the entry back: admins can,
// everyone else needs write access at the place it came from.
func canRestore(u *auth.User, originalPath string) bool {
	if u == nil {
		return false
	}
	if u.Admin {
		return true
	}
	return u.EffectiveLevel(Clean(originalPath)) >= auth.AccessWrite
}

// readTrashMeta loads .<id>.json; ok is false when the record is absent or
// unreadable, which simply hides the item.
func (f *FS) readTrashMeta(trash, id string) (TrashMeta, bool) {
	raw, err := os.ReadFile(filepath.Join(trash, "."+id+".json"))
	if err != nil {
		return TrashMeta{}, false
	}
	var meta TrashMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return TrashMeta{}, false
	}
	return meta, true
}

// trashIDOf extracts the id from an item name (id-originalName); record
// files are dot-prefixed and never parse as items.
func trashIDOf(itemName string) string {
	if len(itemName) < trashIDLen+2 || itemName[trashIDLen] != '-' {
		return ""
	}
	for _, c := range itemName[:trashIDLen] {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			return ""
		}
	}
	return itemName[:trashIDLen]
}

// RestoreTrash moves a trashed entry back to the place it came from. The
// destination directory is recreated if it vanished with the rest of the
// tree, which handles the common case of trashing a folder and later
// restoring one of its contents.
func (f *FS) RestoreTrash(u *auth.User, itemName string) error {
	if u == nil || u.Disabled {
		return ErrForbidden
	}
	trash, err := f.trashDir()
	if err != nil {
		return err
	}
	item := SafeTrashName(itemName)
	if item == "" {
		return ErrNotExist
	}
	meta, ok := f.readTrashMeta(trash, trashIDOf(item))
	if !ok || meta.ID == "" {
		return ErrNotExist
	}
	if !u.Admin && !canRestore(u, meta.OriginalPath) {
		return ErrForbidden
	}

	dst, err := f.restoreTarget(u, meta.OriginalPath)
	if err != nil {
		return err
	}
	itemPath := filepath.Join(trash, item)
	// Each kind moves by the primitive that cannot clobber. Files and
	// symlinks: a hard link claims the destination only when the name is
	// free, then the trash copy is unlinked. Directories cannot be linked,
	// so they rename; rename would replace an empty directory, so an
	// occupancy check runs first and anything present at the destination is
	// an error the caller sees (restore never overwrites).
	info, err := os.Lstat(itemPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if _, serr := os.Lstat(dst); serr == nil {
			return os.ErrExist
		}
		if err := os.Rename(itemPath, dst); err != nil {
			return err
		}
	} else {
		if lerr := os.Link(itemPath, dst); lerr != nil {
			if errors.Is(lerr, os.ErrExist) {
				return os.ErrExist
			}
			return lerr
		}
		if err := os.Remove(itemPath); err != nil {
			return err
		}
	}
	_ = os.Remove(filepath.Join(trash, "."+meta.ID+".json"))
	return nil
}

// restoreTarget turns the recorded virtual path into the real destination,
// recreating a vanished destination directory chain, and re-checks
// containment after the chain exists so a raced symlink cannot redirect it.
func (f *FS) restoreTarget(u *auth.User, originalPath string) (string, error) {
	vp := Clean(originalPath)
	if vp == "/" || vp == "" {
		return "", ErrForbidden
	}
	if isReservedName(path.Base(vp)) {
		return "", ErrReserved
	}
	if !u.Admin && u.EffectiveLevel(parentDir(vp)) < auth.AccessWrite {
		return "", ErrForbidden
	}
	dst := filepath.Join(f.realRoot, filepath.FromSlash(strings.TrimPrefix(vp, "/")))
	if !within(f.realRoot, resolveFor(dst)) {
		return "", ErrForbidden
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	if !within(f.realRoot, resolveFor(dst)) {
		return "", ErrForbidden
	}
	return dst, nil
}

func parentDir(vp string) string {
	if vp == "/" {
		return "/"
	}
	return Clean(path.Dir(vp))
}

// TrashDelete removes one trashed entry (and its record) forever. Restore
// rights on the item are the gate: the same people who could restore it can
// also shred it.
func (f *FS) TrashDelete(u *auth.User, itemName string) error {
	if u == nil || u.Disabled {
		return ErrForbidden
	}
	trash, err := f.trashDir()
	if err != nil {
		return err
	}
	item := SafeTrashName(itemName)
	if item == "" {
		return ErrNotExist
	}
	meta, ok := f.readTrashMeta(trash, trashIDOf(item))
	if !ok {
		return ErrNotExist
	}
	if !u.Admin && !canRestore(u, meta.OriginalPath) {
		return ErrForbidden
	}
	if err := os.RemoveAll(filepath.Join(trash, item)); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(trash, "."+meta.ID+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// TrashPurge wipes the whole trash directory. Admins only: it is the one
// trash operation you cannot take back.
func (f *FS) TrashPurge(u *auth.User) error {
	if u == nil || !u.Admin {
		return ErrForbidden
	}
	trash, err := f.trashDir()
	if err != nil {
		return err
	}
	if err := os.RemoveAll(trash); err != nil {
		return err
	}
	return os.MkdirAll(trash, 0o700)
}

// SafeTrashName keeps a client-supplied trash item name to a plain file
// name: no slash, no traversal, no dot trickery.
func SafeTrashName(name string) string {
	if name == "" || strings.ContainsAny(name, "/\\") || strings.ContainsRune(name, 0) {
		return ""
	}
	if name == "." || name == ".." {
		return ""
	}
	return name
}

// TrashSweep carries out retention: entries whose sidecar record proves
// they have been in the trash longer than maxAge are erased, item and
// record together. It returns how many entries it removed.
//
// Two things are deliberately out of scope. Entries without a record (a
// crash, or an out-of-band drop into the trash directory) have no
// knowable age, so they are left for the hands-on wipe rather than
// guessed at. And recordless sidecars, records with nothing matching
// their item, are invisible housekeeping noise: the sweep lets them be,
// since they hold no content.
func (f *FS) TrashSweep(maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	trash := filepath.Join(f.root, trashDirName)
	des, err := os.ReadDir(trash)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil // no trash yet: nothing to retain
		}
		return 0, err
	}

	cutoff := time.Now().UTC().Add(-maxAge)
	type old struct{ item, record string }
	var doomed []old
	for _, de := range des {
		name := de.Name()
		if name != "" && name[0] == '.' {
			continue // records go with their item, one pass, one way
		}
		id := trashIDOf(name)
		if id == "" {
			continue // no record, no age, no guess
		}
		meta, ok := f.readTrashMeta(trash, id)
		if !ok {
			continue
		}
		if meta.DeletedAt.After(cutoff) {
			continue // young enough to keep
		}
		doomed = append(doomed, old{item: name, record: "." + id + ".json"})
	}

	removed := 0
	for _, d := range doomed {
		if err := os.RemoveAll(filepath.Join(trash, d.item)); err != nil {
			return removed, err
		}
		if err := os.Remove(filepath.Join(trash, d.record)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
