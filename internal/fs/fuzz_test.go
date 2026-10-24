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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// FuzzJoin pins the contract every path-building call site rests on: a plain
// name produces exactly the clean path that name and dir imply, and anything
// the function refuses is refused with ErrForbidden and nothing else.
func FuzzJoin(f *testing.F) {
	for _, seed := range []struct{ dir, name string }{
		{"/", "docs"}, {"docs", "readme.txt"},
		{"/", ".."}, {"/", "."}, {"/", ""}, {"/", "a/b"},
		{"/", "a\\b"}, {"docs/../..", "etc"}, {"docs//", "x"},
		{"/", "photos/2024"}, {"docs", "\x00"}, {"/", "..%2F"},
		{"/", "\xc3\xa9.txt"}, {"/", "  "}, {"//docs", "x"},
	} {
		f.Add(seed.dir, seed.name)
	}

	f.Fuzz(func(t *testing.T, dir, name string) {
		out, err := Join(dir, name)

		bad := name == "" || name == "." || name == ".." ||
			strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0)
		if bad {
			if err == nil {
				t.Fatalf("Join(%q, %q) must refuse a non-plain name", dir, name)
			}
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("refusal for %q must be ErrForbidden, got %v", name, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("Join(%q, %q) refused a plain name: %v", dir, name, err)
		}

		// The output is exactly what the caller asked for, in its clean
		// lexical form: cleaning it again changes nothing, and the child
		// sits directly under the cleaned dir.
		if p := Clean(out); p != out {
			t.Fatalf("Join(%q, %q) = %q, not a clean path", dir, name, out)
		}
		cdir := Clean(dir)
		want := cdir + "/" + name
		if cdir == "/" {
			want = "/" + name
		}
		if out != want {
			t.Fatalf("Join(%q, %q) = %q, want %q", dir, name, out, want)
		}
	})
}

// FuzzResolve drives the virtual path through the whole read path against a
// real tree, including an in-root link and a link out of the tree, and holds
// the security invariant: whenever Resolve hands back a path, the kernel-
// resolved form of that path is inside the root, and the outside secret is
// never reachable no matter what the path text does.
func FuzzResolve(f *testing.F) {
	root, err := os.MkdirTemp("", "filebrowser-fuzz-*")
	if err != nil {
		f.Fatalf("temp tree: %v", err)
	}
	f.Cleanup(func() { os.RemoveAll(root) })

	// The standard fixture, plus an out link whose target sits next to the
	// tree, and an in-root link. resolveExisting follows real links, so the
	// invariants run against real filesystem behaviour.
	mkdirs := []string{"docs/private", "photos/2024", "empty"}
	for _, d := range mkdirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			f.Fatalf("mkdir %s: %v", d, err)
		}
	}
	files := map[string]string{
		"docs/readme.txt":         "hello",
		"docs/private/secret.txt": "classified",
		"photos/2024/a.jpg":       "JPEGDATA",
		"photos/b.png":            "PNGDATA",
	}
	for p, content := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			f.Fatalf("write %s: %v", p, err)
		}
	}
	escape := filepath.Join(filepath.Dir(root), "fuzz-escape")
	if err := os.MkdirAll(escape, 0o700); err != nil {
		f.Fatalf("mkdir escape: %v", err)
	}
	if err := os.WriteFile(filepath.Join(escape, "secret.txt"), []byte("classified"), 0o600); err != nil {
		f.Fatalf("write escape: %v", err)
	}
	if err := os.Symlink(escape, filepath.Join(root, "link-out")); err != nil {
		f.Fatalf("symlink escape: %v", err)
	}
	if err := os.Symlink("docs", filepath.Join(root, "docs-link")); err != nil {
		f.Fatalf("symlink inside: %v", err)
	}

	for _, seed := range []string{
		"/", ".", "..", "..", "/docs", "docs/../etc/passwd", "/docs/readme.txt",
		"//docs", "\\etc", "docs\\readme.txt", "photos/2024/../../docs/private/secret.txt",
		"link-out", "link-out/secret.txt", "docs-link/readme.txt", "..//../x",
		"/link-out/../../secret.txt", "docs/priv%20ate", " photos",
		"photos/2024/", "docs/readme.txt/..", "/././.", "\x00", "/etc/passwd",
	} {
		f.Add(seed)
	}

	ffs, err := New(root)
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	u := adminUser()

	f.Fuzz(func(t *testing.T, vpath string) {
		real, rerr := ffs.Resolve(u, vpath, auth.AccessRead)
		if rerr != nil {
			return // refused is always acceptable
		}
		resolved, aerr := resolveExisting(real)
		if aerr != nil {
			return // raced content; Resolve already contained what it found
		}
		if !within(root, resolved) {
			t.Fatalf("Resolve(%q) yielded %q, which resolves outside the root", vpath, resolved)
		}
	})
}
