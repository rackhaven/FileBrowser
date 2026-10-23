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

package config

import (
	"path/filepath"
	"testing"
)

func TestThumbCacheDefaultsBesideDataDir(t *testing.T) {
	// No thumb-cache env: the cache lives inside the data directory.
	t.Setenv("FB_THUMB_CACHE", "")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ThumbCache != filepath.Join(cfg.DataDir, "thumbs") {
		t.Errorf("ThumbCache = %q, want beside DataDir %q", cfg.ThumbCache, cfg.DataDir)
	}

	// Moving the data dir moves the cache with it.
	t.Setenv("FB_DATA_DIR", "/var/lib/files")
	cfg, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ThumbCache != "/var/lib/files/thumbs" {
		t.Errorf("ThumbCache = %q, want /var/lib/files/thumbs", cfg.ThumbCache)
	}

	// An explicit FB_THUMB_CACHE wins over the default.
	t.Setenv("FB_THUMB_CACHE", "/srv/thumb-cache")
	cfg, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ThumbCache != "/srv/thumb-cache" {
		t.Errorf("ThumbCache = %q, want the explicit override", cfg.ThumbCache)
	}
}
