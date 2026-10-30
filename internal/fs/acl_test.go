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
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// The README's own example: photos is shared for writing, except one folder
// inside it that stays read-only.
func photosWriter() *auth.User {
	return &auth.User{Username: "bob", Grants: []auth.Grant{
		{Path: "/photos", Level: auth.AccessWrite},
		{Path: "/photos/private", Level: auth.AccessRead},
	}}
}

func newPhotosFS(t *testing.T) (*FS, string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "photos/private/secret.jpg", "keep")
	writeFile(t, root, "photos/sub/locked/a.txt", "keep")
	writeFile(t, root, "photos/free.jpg", "mine")
	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f, f.Root()
}

// TestRemoveRefusesFolderHoldingStricterRule: write on a folder must not
// reach a read-only rule inside it by deleting the folder whole.
func TestRemoveRefusesFolderHoldingStricterRule(t *testing.T) {
	f, root := newPhotosFS(t)
	u := photosWriter()

	if err := f.Remove(u, "/photos"); !errIs(ErrForbidden, err) {
		t.Fatalf("delete of a folder holding a read-only rule = %v, want forbidden", err)
	}
	if _, err := os.Stat(filepath.Join(root, "photos/private/secret.jpg")); err != nil {
		t.Fatalf("protected file must still be in place: %v", err)
	}
	// Everything the rule does not cover stays deletable.
	if err := f.Remove(u, "/photos/free.jpg"); err != nil {
		t.Fatalf("delete of an ordinary file = %v", err)
	}
	if err := f.Remove(u, "/photos/sub/locked/a.txt"); err != nil {
		// write on /photos, no rule on /photos/sub/locked here
		t.Fatalf("delete outside the rule = %v", err)
	}
	if err := f.Remove(adminUser(), "/photos"); err != nil {
		t.Fatalf("an administrator ignores rules: %v", err)
	}
}

// TestRenameRefusesFolderHoldingStricterRule: rules are bound to paths, so
// renaming a parent would silently lift the rule from everything inside.
func TestRenameRefusesFolderHoldingStricterRule(t *testing.T) {
	f, _ := newPhotosFS(t)
	u := &auth.User{Username: "bob", Grants: []auth.Grant{
		{Path: "/photos", Level: auth.AccessWrite},
		{Path: "/photos/sub/locked", Level: auth.AccessRead},
	}}

	if _, err := f.Rename(u, "/photos/sub", "/photos", "sub2", false); !errIs(ErrForbidden, err) {
		t.Fatalf("rename of a folder holding a read-only rule = %v, want forbidden", err)
	}
	if _, _, err := f.UploadTarget(u, "/photos/sub/locked", "b.txt", false); !errIs(ErrForbidden, err) {
		t.Fatalf("the rule must still hold after the refused rename: %v", err)
	}
	if _, err := f.Rename(u, "/photos/free.jpg", "/photos", "renamed.jpg", false); err != nil {
		t.Fatalf("rename of an ordinary file = %v", err)
	}
}

// TestOverwriteNeedsWriteOnTheFile: replacing a file writes to it, so a
// read-only rule on the file holds even inside a writable folder.
func TestOverwriteNeedsWriteOnTheFile(t *testing.T) {
	f, _ := newPhotosFS(t)
	u := &auth.User{Username: "bob", Grants: []auth.Grant{
		{Path: "/photos", Level: auth.AccessWrite},
		{Path: "/photos/free.jpg", Level: auth.AccessRead},
	}}
	writeFile(t, f.Root(), "photos/other.jpg", "other")

	if _, _, err := f.UploadTarget(u, "/photos", "free.jpg", true); !errIs(ErrForbidden, err) {
		t.Fatalf("upload over a read-only file = %v, want forbidden", err)
	}
	if _, err := f.Rename(u, "/photos/other.jpg", "/photos", "free.jpg", true); !errIs(ErrForbidden, err) {
		t.Fatalf("move over a read-only file = %v, want forbidden", err)
	}
	if _, _, err := f.UploadTarget(u, "/photos", "other.jpg", true); err != nil {
		t.Fatalf("upload over a writable file = %v", err)
	}
}

// TestTrashEraseRespectsStricterRules: a folder an administrator deleted can
// carry a read-only rule's content into the trash. Someone with write on the
// folder may still restore it, but not shred it.
func TestTrashEraseRespectsStricterRules(t *testing.T) {
	f, _ := newPhotosFS(t)
	if err := f.Remove(adminUser(), "/photos"); err != nil {
		t.Fatalf("admin delete: %v", err)
	}
	u := photosWriter()

	entries, err := f.TrashList(u)
	if err != nil || len(entries) != 1 {
		t.Fatalf("TrashList = %v, %v; want one entry", entries, err)
	}
	e := entries[0]
	if !e.CanRestore || e.CanErase {
		t.Fatalf("can_restore=%v can_erase=%v, want true/false", e.CanRestore, e.CanErase)
	}
	if err := f.TrashDelete(u, e.Name); !errIs(ErrForbidden, err) {
		t.Fatalf("erase = %v, want forbidden", err)
	}
	if err := f.TrashDelete(adminUser(), e.Name); err != nil {
		t.Fatalf("admin erase = %v", err)
	}
}

func needSymlinks(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
}

// newLinkFS has /public/link pointing at /private, the shape an operator
// gets by linking one share into another.
func newLinkFS(t *testing.T) (*FS, string) {
	t.Helper()
	needSymlinks(t)
	root := t.TempDir()
	writeFile(t, root, "public/hello.txt", "hi")
	writeFile(t, root, "private/secret.txt", "SECRET")
	if err := os.Symlink("../private", filepath.Join(root, "public/link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f, f.Root()
}

// TestSymlinkLendsNoAccess: a link inside a readable folder must not hand
// its reader what the link points at. Every read path is checked: download,
// info, listing, search, zip and copy.
func TestSymlinkLendsNoAccess(t *testing.T) {
	f, _ := newLinkFS(t)
	u := &auth.User{Username: "bob", Grants: []auth.Grant{{Path: "/public", Level: auth.AccessWrite}}}

	if fh, _, err := f.Open(u, "/public/link/secret.txt"); err == nil {
		fh.Close()
		t.Fatal("download through the link must be refused")
	}
	if _, err := f.Info(u, "/public/link/secret.txt"); err == nil {
		t.Fatal("info through the link must be refused")
	}
	if _, err := f.List(u, "/public/link"); err == nil {
		t.Fatal("listing through the link must be refused")
	}
	entries, err := f.List(u, "/public")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		if e.Name == "link" {
			t.Fatalf("listing advertised a link to an unreadable place: %+v", e)
		}
	}
	found, err := f.Search(u, "/public", "secret")
	if err != nil || len(found.Entries) != 0 {
		t.Fatalf("search reached through the link: %+v, %v", found.Entries, err)
	}
	var zipped strings.Builder
	if err := f.Zip(u, "/public", &zipped); err != nil {
		t.Fatalf("Zip: %v", err)
	}
	if strings.Contains(zipped.String(), "secret.txt") {
		t.Fatal("zip included a file reached through the link")
	}
	if _, err := f.Copy(u, "/public/link/secret.txt", "/public", "stolen.txt"); err == nil {
		t.Fatal("copy through the link must be refused")
	}
	if _, err := f.Thumbnail(u, "/public/link/secret.txt"); err == nil {
		t.Fatal("thumbnail through the link must be refused")
	}
}

// TestSymlinkWorksWhenTargetIsGranted: links keep working for anyone who
// could reach the target anyway, which is what keeps existing layouts alive.
func TestSymlinkWorksWhenTargetIsGranted(t *testing.T) {
	f, _ := newLinkFS(t)
	u := &auth.User{Username: "bob", Grants: []auth.Grant{
		{Path: "/public", Level: auth.AccessWrite},
		{Path: "/private", Level: auth.AccessRead},
	}}

	fh, _, err := f.Open(u, "/public/link/secret.txt")
	if err != nil {
		t.Fatalf("download through a link to a readable place: %v", err)
	}
	b, _ := io.ReadAll(fh)
	fh.Close()
	if string(b) != "SECRET" {
		t.Fatalf("read %q", b)
	}

	// Through the link the user holds the weaker of the two levels: read.
	entries, err := f.List(u, "/public")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var link *Entry
	for i := range entries {
		if entries[i].Name == "link" {
			link = &entries[i]
		}
	}
	if link == nil || link.Access != "read" {
		t.Fatalf("link row = %+v, want access read", link)
	}
	if got := f.Level(u, "/public/link"); got != auth.AccessRead {
		t.Fatalf("Level through the link = %v, want read", got)
	}
	if _, _, err := f.UploadTarget(u, "/public/link", "new.txt", false); err == nil {
		t.Fatal("upload through a link into a read-only place must be refused")
	}
}

// TestSymlinkIsDeletedWhereItSits: removing or renaming a link moves the
// link itself, so only the folder holding it matters; the target is left
// alone even when the user could not touch it.
func TestSymlinkIsDeletedWhereItSits(t *testing.T) {
	f, root := newLinkFS(t)
	u := &auth.User{Username: "bob", Grants: []auth.Grant{{Path: "/public", Level: auth.AccessWrite}}}

	if _, err := f.Rename(u, "/public/link", "/public", "link2", false); err != nil {
		t.Fatalf("rename of a link in a writable folder: %v", err)
	}
	if err := f.Remove(u, "/public/link2"); err != nil {
		t.Fatalf("delete of a link in a writable folder: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "private/secret.txt")); err != nil {
		t.Fatalf("the link's target must be untouched: %v", err)
	}
}
