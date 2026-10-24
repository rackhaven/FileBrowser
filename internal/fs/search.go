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
	"os"
	"path/filepath"
	"strings"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// SearchLimit is the most matches a single search returns. A drawer of more
// rows is not navigable anyway, and the cap bounds the cost of a pathological
// query against a pathological tree.
const SearchLimit = 300

// SearchOut is one search's page of results.
type SearchOut struct {
	// Entries are the matches in discovery order (a folder's contents follow
	// the folder, so related items sit together).
	Entries []Entry
	// More reports that matches were cut off at SearchLimit.
	More bool
}

// Search returns entries beneath vpath whose names contain substr, case
// insensitively, with the visibility rules of List: readable files only,
// pass-through folders entered for what lies beneath, upload temporaries
// hidden, and symlinks verified the same way before their row is offered.
//
// The match set is bounded by SearchLimit, so the cost is roughly the cost of
// walking the visible tree, not of streaming it; Usage already makes the same
// trade on the dashboard.
func (f *FS) Search(u *auth.User, vpath, substr string) (SearchOut, error) {
	substr = strings.ToLower(strings.TrimSpace(substr))
	if substr == "" {
		return SearchOut{}, nil
	}

	vp := Clean(vpath)
	startDir, err := f.ResolveForList(u, vp)
	if err != nil {
		return SearchOut{}, err
	}

	out := SearchOut{Entries: make([]Entry, 0, 32)}
	var walk func(realDir, vDir string) error
	walk = func(realDir, vDir string) error {
		des, err := os.ReadDir(realDir)
		if err != nil {
			// A folder the OS won't show (or that vanished mid-search)
			// contributes nothing rather than failing the whole search.
			return nil
		}
		for _, de := range des {
			if out.More {
				return nil // keep the walk cheap once the page is full
			}
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

			// A symlink must first prove it stays in the root, exactly as in
			// List, or its row would 404 or, worse, offer outside content.
			if info.Mode()&os.ModeSymlink != 0 {
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

			level := u.EffectiveLevel(childVP)
			readable := level >= auth.AccessRead
			partial := !readable && info.IsDir() && u.HasAnyGrantUnder(childVP)
			if !readable && !partial {
				continue
			}

			if strings.Contains(strings.ToLower(name), substr) {
				if len(out.Entries) >= SearchLimit {
					out.More = true
					return nil
				}
				out.Entries = append(out.Entries, Entry{
					Name:    name,
					Path:    childVP,
					IsDir:   info.IsDir(),
					Access:  level.String(),
					Partial: partial,
					Size:    info.Size(),
					ModTime: info.ModTime(),
					Mode:    info.Mode().String(),
				})
			}

			if info.IsDir() {
				if werr := walk(filepath.Join(realDir, name), childVP); werr != nil {
					return werr
				}
			}
		}
		return nil
	}

	if werr := walk(startDir, vp); werr != nil {
		return SearchOut{}, werr
	}
	return out, nil
}
