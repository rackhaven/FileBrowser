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

//go:build !linux

package fs

import (
	"os"
	"path/filepath"
)

// On platforms without openat2 the containment still rests on Resolve and
// its re-check; the open itself is an ordinary path open. No behaviour
// changes for them.
func openInside(root, rel string, flags int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(filepath.Join(root, filepath.FromSlash(rel)), flags, perm)
}
