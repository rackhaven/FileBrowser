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

//go:build linux

package fs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestOpenInsideRefusesEscapeLinks pins the kernel-side containment: openat2
// refuses no matter how a symlink lands in the walk, while links that stay
// inside the root keep working exactly as before.
func TestOpenInsideRefusesEscapeLinks(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "docs/readme.txt", "hello")

	// A second, unrelated directory outside the root holds a secret. It is
	// created as a sibling of the root so the races cannot be explained away
	// by storage layout.
	outside := filepath.Join(filepath.Dir(root), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("classified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "outlink")); err != nil {
		t.Fatal(err)
	}
	// A chain: an in-root link that names another link that points out.
	if err := os.Symlink("outlink", filepath.Join(root, "out-link")); err != nil {
		t.Fatal(err)
	}

	// Through the link, at the link itself, or along a chained link: the
	// kernel cannot be made to open the secret. The exact error depends on
	// where the walk is refused: an absolute-target link is reanchored under
	// the root and misses (a chroot-style not-found), while loops make
	// ELOOP, which the wrapper reports as a permission error.
	for _, rel := range []string{
		"outlink/secret.txt",
		"outlink",
		"out-link/secret.txt",
	} {
		_, err := openInside(f.realRoot, rel, os.O_RDONLY, 0)
		if err == nil {
			t.Errorf("open outside via %q: opened, must refuse", rel)
			continue
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			t.Errorf("open outside via %q: %v, want a refusal error", rel, err)
		}
	}

	// Walks above the root are clamped: an attempt to leave and come back
	// answers with whichever refusal applies, never with outside content.
	if _, err := openInside(f.realRoot, "../outside/secret.txt", os.O_RDONLY, 0); err == nil {
		t.Error("open of ../outside/secret.txt succeeded: outside content must not open")
	}

	// Inside links still work: an alias to the docs folder resolves to a
	// readable path the direct form also gets to.
	if err := os.Symlink("docs", filepath.Join(root, "docs-link")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"docs/readme.txt", "docs-link/readme.txt"} {
		file, err := openInside(f.realRoot, rel, os.O_RDONLY, 0)
		if err != nil {
			t.Errorf("open of %q: %v", rel, err)
			continue
		}
		file.Close()
	}

	// The whole FS sits on top of this: Open goes through the same
	// openat2 path and must behave identically for read access.
	u := adminUser()
	file, info, err := f.Open(u, "/docs/readme.txt")
	if err != nil {
		t.Fatalf("Open docs/readme.txt: %v", err)
	}
	if info.Name() != "readme.txt" {
		t.Errorf("Open named %q", info.Name())
	}
	file.Close()

	// A symlink chain inside the root, accessed through the download path.
	if err := os.Symlink("docs", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	file, _, err = f.Open(u, "/alias/readme.txt")
	if err != nil {
		t.Errorf("Open alias/readme.txt: %v", err)
	} else {
		file.Close()
	}
}

// TestDirAtAndSelfPath checks the mechanical corners: the root itself opens
// as ".", and a missing name is a plain not-exist.
func TestDirAtAndSelfPath(t *testing.T) {
	f := newTestFS(t)

	dirFD, err := dirAt(f.realRoot)
	if err != nil {
		t.Fatalf("dirAt: %v", err)
	}
	defer unix.Close(dirFD)
	file, err := fileAt(dirFD, ".", os.O_RDONLY, 0)
	if err != nil {
		t.Errorf("fileAt .: %v", err)
	} else {
		file.Close()
	}
	file, err = fileAt(dirFD, "/docs//readme.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Errorf("fileAt doubled slashes: %v", err)
	} else {
		file.Close()
	}
	if file, err := fileAt(dirFD, "no/such/file", os.O_RDONLY, 0); !errors.Is(err, os.ErrNotExist) {
		if file != nil {
			file.Close()
		}
		t.Errorf("missing file: %v, want not-exist", err)
	}
}
