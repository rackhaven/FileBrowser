// Command filebrowser serves a private, authenticated file browser over HTTP.
//
// Usage:
//
//	filebrowser [serve] [flags]
//	filebrowser user add <username> [--admin] [--grant /path:level]
//	filebrowser user passwd <username>
//	filebrowser user rm <username>
//	filebrowser user list
//	filebrowser version

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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rackhaven/filebrowser/internal/auth"
	"github.com/rackhaven/filebrowser/internal/config"
	"github.com/rackhaven/filebrowser/internal/fs"
	"github.com/rackhaven/filebrowser/internal/server"
	"github.com/rackhaven/filebrowser/web"
)

// version is overridable at build time: -ldflags "-X main.version=1.2.3"
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// Subcommands come first so "filebrowser user list" does not try to parse
	// flags intended for serve.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "serve":
			return runServe(args[1:])
		case "user":
			return runUser(args[1:])
		case "version", "--version", "-v":
			fmt.Println("filebrowser", version)
			return nil
		case "help", "--help", "-h":
			usage()
			return nil
		default:
			return fmt.Errorf("unknown command %q (did you mean %q?)", args[0], "serve")
		}
	}
	return runServe(args)
}

func usage() {
	fmt.Fprint(os.Stderr, `filebrowser - a private file browser

Usage:
  filebrowser [serve] [flags]        start the HTTP server (default)
  filebrowser user add [flags] <name>   create an account
  filebrowser user passwd <name>        set a password
  filebrowser user rm <name>            delete an account
  filebrowser user list                 list accounts
  filebrowser version                   print the version

Serve flags:
  -config string   path to a YAML config file
  -listen string   address to bind (default 0.0.0.0:8080)
  -root string     directory to expose (default /srv/files)
  -data string     directory holding the user database (default /data)

User flags (place them before the username):
  -admin           make the account an administrator with access to everything
  -grant string    access rules, e.g. -grant /photos:read,/docs:write
                   levels: read, write, admin

Passwords are always prompted for; they are never accepted as arguments,
because command lines are visible to other processes and shell history.

Environment: FB_LISTEN, FB_ROOT, FB_DATA_DIR, FB_SESSION_TTL, FB_TLS_CERT,
FB_TLS_KEY, FB_TRUST_PROXY_HEADERS, FB_MAX_UPLOAD_BYTES, FB_LOG_LEVEL,
FB_ADMIN_USER, FB_ADMIN_PASSWORD
`)
}

// ------------------------------------------------------------- serve ------

func runServe(args []string) error {
	// args has already had any subcommand stripped by run. Flag parsing stops
	// at the first non-flag argument, which is why run must remove "serve"
	// before we get here: "serve -root /data" would otherwise ignore every flag.
	fs_ := flag.NewFlagSet("serve", flag.ContinueOnError)
	var (
		configPath = fs_.String("config", "", "path to a YAML config file")
		listen     = fs_.String("listen", "", "address to bind")
		root       = fs_.String("root", "", "directory to expose")
		dataDir    = fs_.String("data", "", "directory for the user database")
	)
	if err := fs_.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	// Flags beat both the config file and the environment.
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *root != "" {
		cfg.Root = filepath.Clean(*root)
	}
	if *dataDir != "" {
		cfg.DataDir = filepath.Clean(*dataDir)
	}

	logger := newLogger()

	store, err := auth.OpenStore(filepath.Join(cfg.DataDir, "users.json"))
	if err != nil {
		return err
	}
	if err := bootstrapAdmin(store, cfg.DataDir, logger); err != nil {
		return err
	}

	files, err := fs.New(cfg.Root)
	if err != nil {
		return err
	}

	sessions := auth.NewSessions(cfg.SessionTTL)
	srv := server.New(server.Options{
		Config: server.Config{
			TrustProxyHeaders: cfg.TrustProxyHeaders,
			SessionTTL:        cfg.SessionTTL,
			MaxUploadBytes:    cfg.MaxUploadBytes,
		},
		Users:    store,
		Sessions: sessions,
		FS:       files,
		Static:   web.Static(),
		Version:  version,
		Logger:   logger,
	})

	httpServer := &http.Server{
		Addr:    cfg.Listen,
		Handler: srv.Handler(),
		// No write timeout: downloads of multi-gigabyte files must be allowed
		// to take as long as they need. ReadHeaderTimeout still bounds the
		// slowloris window, and IdleTimeout reclaims dead keep-alives.
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	scheme := "http"
	if cfg.TLSCert != "" {
		scheme = "https"
	}
	logger.Info("starting",
		"version", version,
		"addr", cfg.Listen,
		"root", files.Root(),
		"data", cfg.DataDir,
		"url", fmt.Sprintf("%s://%s", scheme, cfg.Listen),
	)

	errCh := make(chan error, 1)
	go func() {
		var err error
		if cfg.TLSCert != "" {
			err = httpServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			err = httpServer.ListenAndServe()
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	// Wait for a signal or a server error, whichever comes first.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		logger.Info("shutting down", "signal", sig.String())
	}

	// Give in-flight downloads a chance to finish before dropping connections.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		return err
	}
	return <-errCh
}

// newLogger builds a human-readable logger, honouring FB_LOG_LEVEL.
func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("FB_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// bootstrapAdmin makes sure at least one administrator exists.
//
// On a fresh install with no credentials configured we generate a strong random
// password and print it once. That is safer than shipping a default password,
// and the operator can always override it with FB_ADMIN_USER/FB_ADMIN_PASSWORD.
func bootstrapAdmin(store *auth.Store, dataDir string, logger *slog.Logger) error {
	if store.Count() > 0 {
		return nil
	}

	name := strings.TrimSpace(os.Getenv("FB_ADMIN_USER"))
	password := os.Getenv("FB_ADMIN_PASSWORD")

	generated := false
	if name == "" || password == "" {
		if name == "" {
			name = "admin"
		}
		if password == "" {
			random, err := auth.RandomToken(12)
			if err != nil {
				return err
			}
			password = random
			generated = true
		}
	}

	if _, err := store.Create(name, password, true, nil); err != nil {
		return fmt.Errorf("could not create the initial administrator: %w", err)
	}

	if generated {
		// Printed to stdout because there is no UI yet to show it in.
		fmt.Fprintln(os.Stderr, strings.Repeat("=", 68))
		fmt.Fprintf(os.Stderr, "  Created the first administrator account.\n\n")
		fmt.Fprintf(os.Stderr, "    username: %s\n", name)
		fmt.Fprintf(os.Stderr, "    password: %s\n\n", password)
		fmt.Fprintln(os.Stderr, "  This is shown once. Sign in and change it now.")
		fmt.Fprintln(os.Stderr, strings.Repeat("=", 68))
	} else {
		logger.Info("created the initial administrator", "user", name)
	}

	if err := os.Chmod(filepath.Join(dataDir, "users.json"), 0o600); err != nil {
		logger.Warn("could not tighten permissions on the user database", "err", err)
	}
	return nil
}

// -------------------------------------------------------------- user ------

func runUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: filebrowser user <add|passwd|rm|list>")
	}

	cmd, rest := args[0], args[1:]

	// Go's flag package stops at the first non-flag argument, so flags have to
	// precede the username: "user add --admin alice", not "user add alice
	// --admin". Partition the arguments so a flag in the wrong position is a
	// clear error rather than being silently ignored.
	flags, positional := splitFlags(rest)

	fset := flag.NewFlagSet("user "+cmd, flag.ContinueOnError)
	var (
		isAdmin = fset.Bool("admin", false, "grant full access to the root")
		grants  = fset.String("grant", "", "comma-separated rules, e.g. /photos:read,/docs:write")
		dataDir = fset.String("data", envOr("FB_DATA_DIR", "/data"), "directory for the user database")
	)
	if err := fset.Parse(flags); err != nil {
		return err
	}
	// splitFlags already pulled out the flags; whatever the flag package did
	// not consume joins them back as positional arguments.
	argsLeft := append(positional, fset.Args()...)

	username := ""
	if len(argsLeft) > 0 {
		username = strings.TrimSpace(argsLeft[0])
	}
	if len(argsLeft) > 1 {
		return fmt.Errorf("unexpected argument %q", argsLeft[1])
	}

	if cmd == "list" {
		if username != "" {
			return errors.New("usage: filebrowser user list")
		}
	} else if username == "" {
		return fmt.Errorf("usage: filebrowser user %s [flags] <username>", cmd)
	}

	store, err := auth.OpenStore(filepath.Join(filepath.Clean(*dataDir), "users.json"))
	if err != nil {
		return err
	}
	// Hold the advisory lock for the whole command: the server coordinates
	// through the same lock file, so an edit cannot interleave with (or be
	// overwritten by) a live server's own write.
	if err := store.LockExclusive(); err != nil {
		return err
	}
	defer func() { _ = store.Unlock() }()

	switch cmd {
	case "add":
		// Validate everything cheap before prompting, so a typo in the
		// username does not cost the user a password entry.
		if !auth.ValidUsername(username) {
			return auth.ErrBadUsername
		}
		if _, err := store.GetByUsername(username); err == nil {
			return auth.ErrUserExists
		}
		parsed, err := parseGrants(*grants)
		if err != nil {
			return err
		}

		password, err := readPassword()
		if err != nil {
			return err
		}
		created, err := store.Create(username, password, *isAdmin, parsed)
		if err != nil {
			return err
		}
		fmt.Printf("created user %s (admin=%v)\n", created.Username, created.Admin)
		for _, g := range created.Grants {
			fmt.Printf("  %s  %s\n", g.Path, g.Level)
		}
		return nil

	case "passwd":
		u, err := store.GetByUsername(username)
		if err != nil {
			return err
		}
		password, err := readPassword()
		if err != nil {
			return err
		}
		// Always force a change: an administrator resetting a password should
		// not leave the account on a password the user has never seen.
		if err := store.SetPassword(u.ID, password, true); err != nil {
			return err
		}
		fmt.Printf("password updated for %s; they must change it at next sign-in\n", u.Username)
		return nil

	case "rm":
		u, err := store.GetByUsername(username)
		if err != nil {
			return err
		}
		if err := store.Delete(u.ID); err != nil {
			return err
		}
		fmt.Printf("deleted user %s\n", u.Username)
		return nil

	case "list":
		users := store.List()
		if len(users) == 0 {
			fmt.Println("no users configured")
			return nil
		}
		for _, u := range users {
			role := "user"
			if u.Admin {
				role = "admin"
			}
			state := ""
			if u.Disabled {
				state = " (disabled)"
			}
			fmt.Printf("%-20s %-6s%s\n", u.Username, role, state)
			for _, g := range u.Grants {
				fmt.Printf("    %-30s %s\n", g.Path, g.Level)
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown user command %q", cmd)
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// readPassword prompts twice for a password.
//
// There is deliberately no flag to supply it on the command line: argv is
// world-readable through /proc and shows up in shell history and the audit
// log. Provision scripts should set FB_ADMIN_PASSWORD on first start, or call
// the admin API.
func readPassword() (string, error) {
	fmt.Fprint(os.Stderr, "password: ")
	first, err := readLine()
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "confirm:  ")
	second, err := readLine()
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("passwords do not match")
	}
	if !auth.ValidPassword(first) {
		return "", auth.ErrBadPassword
	}
	return first, nil
}

// splitFlags separates flag arguments from positional ones so that a flag
// written after the username is still recognised. Boolean flags may legally
// appear without a value.
func splitFlags(args []string) (flags, positional []string) {
	valueFlags := map[string]bool{
		"-grant": true, "--grant": true,
		"-data": true, "--data": true,
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" || a == "--" {
			positional = append(positional, a)
			continue
		}

		name := a
		if eq := strings.Index(a, "="); eq > 0 {
			name = a[:eq]
		}
		flags = append(flags, a)

		// A value flag without "=" consumes the next argument.
		if !strings.Contains(a, "=") && valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, positional
}

// parseGrants turns "-grant /photos:read,/docs:write" into rules.
func parseGrants(s string) ([]auth.Grant, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []auth.Grant
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.LastIndex(part, ":")
		if idx <= 0 {
			return nil, fmt.Errorf("grant %q should look like /path:level", part)
		}
		level, err := auth.ParseLevel(part[idx+1:])
		if err != nil {
			return nil, fmt.Errorf("grant %q: %w", part, err)
		}
		out = append(out, auth.Grant{Path: part[:idx], Level: level})
	}
	return out, nil
}
