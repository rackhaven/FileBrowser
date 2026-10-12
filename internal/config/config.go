// Package config loads server configuration from an optional YAML file and
// environment variables. Environment variables always win over the file so a
// container can override baked-in defaults.

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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Listen is the address the HTTP server binds to.
	Listen string `yaml:"listen"`
	// Root is the directory exposed to users. Nothing outside this tree is
	// ever readable, regardless of grants.
	Root string `yaml:"root"`
	// DataDir holds the user database.
	DataDir string `yaml:"data_dir"`
	// SessionTTL is how long a login stays valid.
	SessionTTL time.Duration `yaml:"session_ttl"`
	// TLSCert / TLSKey enable direct TLS (optional; a reverse proxy is
	// usually better because it handles renewals).
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// TrustProxyHeaders honours X-Forwarded-Proto when deciding whether to
	// set the Secure cookie attribute. Only enable behind a proxy you control.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`
	// AllowSignup is intentionally not supported: accounts are created by an
	// admin so the service can never be self-serve on a public network.
}

// Default returns the built-in defaults.
func Default() Config {
	return Config{
		Listen:     "0.0.0.0:8080",
		Root:       "/srv/files",
		DataDir:    "/data",
		SessionTTL: 7 * 24 * time.Hour,
	}
}

// Load reads path (optional), then applies FB_* environment overrides.
// An empty path means "defaults + env".
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config %s: %w", path, err)
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	envStr("FB_LISTEN", &cfg.Listen)
	envStr("FB_ROOT", &cfg.Root)
	envStr("FB_DATA_DIR", &cfg.DataDir)
	envStr("FB_TLS_CERT", &cfg.TLSCert)
	envStr("FB_TLS_KEY", &cfg.TLSKey)
	envBool("FB_TRUST_PROXY_HEADERS", &cfg.TrustProxyHeaders)

	if v, ok := os.LookupEnv("FB_SESSION_TTL"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("FB_SESSION_TTL: %w", err)
		}
		cfg.SessionTTL = d
	}

	if cfg.Listen == "" {
		return cfg, fmt.Errorf("listen address must not be empty")
	}
	if cfg.Root == "" {
		return cfg, fmt.Errorf("root directory must not be empty")
	}
	if cfg.DataDir == "" {
		return cfg, fmt.Errorf("data directory must not be empty")
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return cfg, fmt.Errorf("tls_cert and tls_key must be set together")
	}

	cfg.Root = filepath.Clean(cfg.Root)
	cfg.DataDir = filepath.Clean(cfg.DataDir)
	return cfg, nil
}

func envStr(key string, dst *string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = strings.TrimSpace(v)
	}
}

func envBool(key string, dst *bool) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return // ignore malformed values rather than crashing on a typo
	}
	*dst = b
}
