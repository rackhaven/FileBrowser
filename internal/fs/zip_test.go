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
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// names returns the archive's member names, top-level directory included.
func zipNames(t *testing.T, raw []byte) []string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	return names
}

func TestZipIncludesWholeReadableTree(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, "docs/more/deep.txt", "deep")
	writeFile(t, root, ".upload-4ghost.tmp", "in flight")
	u := user(auth.AccessAdmin)

	var buf bytes.Buffer
	if err := f.Zip(u, "/", &buf); err != nil {
		t.Fatalf("Zip /: %v", err)
	}
	names := zipNames(t, buf.Bytes())
	want := []string{
		"files/docs/readme.txt",
		"files/docs/more/deep.txt",
		"files/photos/2024/a.jpg",
		"files/docs/private/secret.txt",
	}
	for _, w := range want {
		if !slicesContains(names, w) {
			t.Errorf("archive is missing %s; got %v", w, names)
		}
	}
	// In-flight temporaries never belong in an archive.
	if slicesContains(names, "files/.upload-4ghost.tmp") {
		t.Error("archive contains an in-flight upload temporary")
	}
}

func TestZipOmitsInvisibleSubtrees(t *testing.T) {
	f := newTestFS(t)
	// The user may read /docs/private and nothing else. Zipping the root:
	// /docs is only a pass-through, readme.txt is invisible, and /photos and
	// /empty must not appear at all.
	u := user(auth.AccessNone, auth.Grant{Path: "/docs/private", Level: auth.AccessRead})

	var buf bytes.Buffer
	if err := f.Zip(u, "/", &buf); err != nil {
		t.Fatalf("Zip /: %v", err)
	}
	names := zipNames(t, buf.Bytes())
	if len(names) != 1 || names[0] != "files/docs/private/secret.txt" {
		t.Fatalf("archive should hold exactly the private subtree; got %v", names)
	}
}

func TestZipOfDeniedPathFails(t *testing.T) {
	f := newTestFS(t)
	// Grants on /docs give no reach into /photos at all. Built by hand (no
	// root-level grant) so the helper's extra root rule cannot confuse the
	// case with its level-none grant.
	u := &auth.User{Username: "u", Grants: []auth.Grant{
		{Path: "/docs", Level: auth.AccessWrite},
	}}

	var buf bytes.Buffer
	if err := f.Zip(u, "/photos", &buf); err != ErrForbidden {
		t.Fatalf("Zip of a denied path: got %v, want ErrForbidden", err)
	}
}

func TestZipOfAFileIsNotADirectory(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessAdmin)

	var buf bytes.Buffer
	if err := f.Zip(u, "/docs/readme.txt", &buf); err != ErrNotDir {
		t.Fatalf("Zip of a file: got %v, want ErrNotDir", err)
	}
}

func TestZipSkipsTempNamesAndOutsideSymlinks(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	writeFile(t, root, ".upload-skip.tmp", "in flight")
	writeFile(t, root, "keep.txt", "keep")
	if err := os.Symlink("/etc/hostname", filepath.Join(root, "escape")); err != nil {
		t.Skipf("make symlink: %v", err)
	}
	u := user(auth.AccessAdmin)

	var buf bytes.Buffer
	if err := f.Zip(u, "/", &buf); err != nil {
		t.Fatalf("Zip: %v", err)
	}
	names := zipNames(t, buf.Bytes())
	for _, n := range names {
		if strings.HasSuffix(n, ".upload-skip.tmp") {
			t.Error("archive contains an in-flight upload temporary")
		}
		if strings.HasSuffix(n, "/escape") {
			t.Error("archive contains a symlink pointing outside the root")
		}
	}
	if !slicesContains(names, "files/keep.txt") {
		t.Errorf("archive lost a real file; got %v", names)
	}
}

func TestZipUsesTopFolderName(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessAdmin)

	var buf bytes.Buffer
	if err := f.Zip(u, "/docs", &buf); err != nil {
		t.Fatalf("Zip /docs: %v", err)
	}
	for _, n := range zipNames(t, buf.Bytes()) {
		if !strings.HasPrefix(n, "docs/") {
			t.Fatalf("members must sit under docs/, got %v", zipNames(t, buf.Bytes()))
		}
	}
}

func TestZipInfoNamesTheArchive(t *testing.T) {
	f := newTestFS(t)
	u := user(auth.AccessAdmin)

	if got, err := f.ZipInfo(u, "/docs"); err != nil || got != "docs" {
		t.Errorf("ZipInfo /docs = %q, %v; want docs, nil", got, err)
	}
	if got, err := f.ZipInfo(u, "/"); err != nil || got != "files" {
		t.Errorf("ZipInfo / = %q, %v; want files, nil", got, err)
	}
	denied := &auth.User{Username: "u", Grants: []auth.Grant{
		{Path: "/docs", Level: auth.AccessRead},
	}}
	if _, err := f.ZipInfo(denied, "/empty"); err != ErrForbidden {
		t.Errorf("ZipInfo of a denied folder: %v, want ErrForbidden", err)
	}
}

func slicesContains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
