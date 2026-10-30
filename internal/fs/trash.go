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
	// CanErase is CanRestore minus entries that took a stricter rule's
	// content with them: those only an administrator may shred.
	CanErase bool `json:"can_erase"`
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
// The move is moveNoClobber: a rename that never replaces (an id collision
// answers os.ErrExist and a fresh id is drawn), falling back to copy and
// remove when the entry lives on another filesystem than the trash, as a
// disk mounted inside the root does. Earlier versions claimed the trash name
// with a hard link, which FAT and exFAT drives, some network shares and
// fs.protected_hardlinks all refuse, so deletes failed there outright.
//
// Symlinks move as themselves: the trash never follows them.
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

		lastErr = moveNoClobber(real, itemPath)
		switch {
		case lastErr == nil:
			return nil
		case errors.Is(lastErr, errMoveLeftovers):
			// The trash holds a complete copy; keep it and its record,
			// and say the delete did not fully finish.
			return lastErr
		case errors.Is(lastErr, os.ErrExist):
			_ = os.Remove(metaPath)
			continue // an id collision: fresh id, try again
		default:
			_ = os.Remove(metaPath)
			return lastErr
		}
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
		entry.CanErase = admin || canErase(u, meta.OriginalPath)
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

// canErase reports whether the user may destroy the entry for good: restore
// rights, plus write over everything that was beneath it. A folder an
// administrator deleted can hold a read-only rule's content, which someone
// with write on the folder alone must not be able to shred.
func canErase(u *auth.User, originalPath string) bool {
	return canRestore(u, originalPath) && !u.RestrictedBelow(Clean(originalPath), auth.AccessWrite)
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
	// Restore never overwrites: anything present at the destination is an
	// error the caller sees. Across filesystems the move copies, and when
	// the trash copy cannot be fully removed afterwards its record is kept,
	// so the leftover stays visible to whoever can erase it.
	if err := moveNoClobber(itemPath, dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.ErrExist // the bare sentinel, as callers have always had
		}
		return err
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
	// The destination folder is judged where it really lives, so a link
	// on the way back cannot land the entry somewhere the user may not
	// write.
	if _, _, err := f.resolveVP(u, parentDir(vp), auth.AccessWrite); err != nil {
		return "", err
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
// rights on the item are the gate, narrowed by canErase: write must also
// reach every rule that was beneath the entry.
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
	if !u.Admin && !canErase(u, meta.OriginalPath) {
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
