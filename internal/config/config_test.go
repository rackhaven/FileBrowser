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
	"os"
	"path/filepath"
	"testing"
	"time"
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

// TestSetDataDirCarriesDerivedThumbCache: the -data flag is applied after
// Load, and a derived cache must follow it (the shipped systemd unit sets
// the data dir only by flag).
func TestSetDataDirCarriesDerivedThumbCache(t *testing.T) {
	t.Setenv("FB_THUMB_CACHE", "")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetDataDir("/var/lib/filebrowser")
	if cfg.ThumbCache != "/var/lib/filebrowser/thumbs" {
		t.Errorf("ThumbCache = %q, want it moved with the data dir", cfg.ThumbCache)
	}

	t.Setenv("FB_THUMB_CACHE", "/srv/thumb-cache")
	cfg, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetDataDir("/var/lib/filebrowser")
	if cfg.ThumbCache != "/srv/thumb-cache" {
		t.Errorf("ThumbCache = %q, an explicit cache must stay put", cfg.ThumbCache)
	}
}

func TestTrashTTLDefaultsAndOverrides(t *testing.T) {
	// Default: thirty days, so the drawer is a safety net, not an archive.
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrashTTL != 30*24*time.Hour {
		t.Errorf("TrashTTL default = %v, want 720h", cfg.TrashTTL)
	}

	// The environment carries durations like FB_SESSION_TTL does.
	t.Setenv("FB_TRASH_TTL", "48h")
	cfg, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrashTTL != 48*time.Hour {
		t.Errorf("TrashTTL from env = %v, want 48h", cfg.TrashTTL)
	}

	// Zero opts out; negative is a typo, so it fails loudly.
	t.Setenv("FB_TRASH_TTL", "0s")
	cfg, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrashTTL != 0 {
		t.Errorf("TrashTTL = %v, want zero", cfg.TrashTTL)
	}
	t.Setenv("FB_TRASH_TTL", "yesterday")
	if _, err := Load(""); err == nil {
		t.Error("a malformed FB_TRASH_TTL must be an error")
	}

	// The YAML file sets it too, and the environment still wins.
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "listen: 0.0.0.0:9090\nroot: /srv\ndata_dir: /var/lib/fb\ntrash_ttl: 168h\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FB_TRASH_TTL", "") // quietly ignored: the file value must reach through
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrashTTL != 7*24*time.Hour {
		t.Errorf("TrashTTL from file = %v, want 168h", cfg.TrashTTL)
	}
	t.Setenv("FB_TRASH_TTL", "1h")
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrashTTL != time.Hour {
		t.Errorf("TrashTTL env over file = %v, want 1h", cfg.TrashTTL)
	}
}

func TestLogLevelDefaultsAndOverrides(t *testing.T) {
	// Default: info level, a plain empty string.
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "" {
		t.Errorf("LogLevel default = %q, want empty", cfg.LogLevel)
	}

	// A name from the list is accepted as handed (mixed case is fine).
	t.Setenv("FB_LOG_LEVEL", "Warn")
	cfg, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "Warn" {
		t.Errorf("LogLevel from env = %q, want Warn", cfg.LogLevel)
	}

	// Anything else fails loudly rather than logging as nothing at all.
	t.Setenv("FB_LOG_LEVEL", "verbose")
	if _, err := Load(""); err == nil {
		t.Error("an unknown log level must be an error")
	}

	// The YAML sets it too, and the environment still wins.
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("log_level: error\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FB_LOG_LEVEL", "")
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "error" {
		t.Errorf("LogLevel from file = %q, want error", cfg.LogLevel)
	}
	t.Setenv("FB_LOG_LEVEL", "debug")
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel env over file = %q, want debug", cfg.LogLevel)
	}
}
