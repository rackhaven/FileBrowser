// Package web holds the PWA assets. They are embedded into the binary so the
// service is a single self-contained file with no runtime asset dependency.
//
// The asset tree is rooted so that FileServerFS can serve it under /static,
// while index.html, manifest and the service worker are served from their
// well-known root paths, as browsers require.

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

package web

import (
	"embed"
	"io/fs"
)

//go:embed assets
var embedded embed.FS

// Static returns the asset tree rooted at the assets directory.
func Static() fs.FS {
	sub, err := fs.Sub(embedded, "assets")
	if err != nil {
		// Unreachable: the embed directive is checked at build time.
		panic("web: could not open embedded assets: " + err.Error())
	}
	return sub
}
