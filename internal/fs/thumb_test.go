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
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// These fixtures are hand-embedded and the test file deliberately does not
// import image/png or image/gif: importing either would register its decoder
// for the whole test binary and make the missing blank registrations in
// thumb.go invisible to this suite (that failure shipped once already).

// tinyPNG is a valid 1x1 transparent PNG.
var tinyPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
	0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
	0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xdd, 0x8d, 0xb0, 0x00, 0x00, 0x00,
	0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
}

// tinyGIF is a valid 1x1 GIF87a, one red pixel.
var tinyGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x37, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

// makeJPEG encodes a filled colour JPEG of w x h at rel under root (parents
// created as needed) and returns the bytes that landed on disk.
func makeJPEG(t *testing.T, root, rel string, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// A smooth ramp: re-encoded output is distinct per sample.
			img.SetRGBA(x, y, color.RGBA{R: uint8(x % 256), G: uint8(y % 256), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	writeFile(t, root, rel, buf.String())
	return buf.Bytes()
}

func TestThumbnailScalesLargeImages(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	if err := f.SetThumbCache(filepath.Join(t.TempDir(), "thumbs")); err != nil {
		t.Fatalf("SetThumbCache: %v", err)
	}
	makeJPEG(t, root, "photos/big.jpg", 800, 600)
	u := user(auth.AccessAdmin)

	thumb, err := f.Thumbnail(u, "/photos/big.jpg")
	if err != nil {
		t.Fatalf("Thumbnail: %v", err)
	}
	if thumb.ContentType != "image/jpeg" {
		t.Errorf("content type %q, want image/jpeg", thumb.ContentType)
	}
	img, _, err := image.Decode(bytes.NewReader(thumb.Data))
	if err != nil {
		t.Fatalf("decode thumbnail: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != ThumbSize || b.Dy() != ThumbSize*600/800 {
		t.Errorf("scaled to %dx%d, want a 320-edge fit", b.Dx(), b.Dy())
	}
}

func TestThumbnailPassesSmallImagesThrough(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	if err := f.SetThumbCache(t.TempDir()); err != nil {
		t.Fatalf("SetThumbCache: %v", err)
	}
	writeFile(t, root, "photos/tiny.png", string(tinyPNG))
	writeFile(t, root, "photos/tiny.gif", string(tinyGIF))
	u := user(auth.AccessAdmin)

	// This passage-through is also the regression test for the decoder
	// registrations: without all of them the decode fails and the two calls
	// below return ErrNotImage instead of the source bytes.
	thumb, err := f.Thumbnail(u, "/photos/tiny.png")
	if err != nil {
		t.Fatalf("png Thumbnail: %v", err)
	}
	if thumb.ContentType != "image/png" {
		t.Errorf("png content type %q, want the source's image/png", thumb.ContentType)
	}
	if !bytes.Equal(thumb.Data, tinyPNG) {
		t.Error("a small image must come back byte-identical, not re-encoded")
	}

	thumb, err = f.Thumbnail(u, "/photos/tiny.gif")
	if err != nil {
		t.Fatalf("gif Thumbnail: %v", err)
	}
	if thumb.ContentType != "image/gif" {
		t.Errorf("gif content type %q, want the source's image/gif", thumb.ContentType)
	}
	if !bytes.Equal(thumb.Data, tinyGIF) {
		t.Error("a small gif must come back byte-identical")
	}
}

func TestThumbnailUsesAndRefreshesItsCache(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	cache := t.TempDir()
	if err := f.SetThumbCache(cache); err != nil {
		t.Fatalf("SetThumbCache: %v", err)
	}
	u := user(auth.AccessAdmin)

	makeJPEG(t, root, "photos/one.jpg", 900, 700)
	if _, err := f.Thumbnail(u, "/photos/one.jpg"); err != nil {
		t.Fatalf("first Thumbnail: %v", err)
	}
	after, _ := os.ReadDir(cache)
	if len(after) != 1 {
		t.Fatalf("cache holds %d files, want 1", len(after))
	}

	// Rewriting the file must not hit the stale entry: the mtime and size
	// in the key shift, so a second cache file appears and the preview
	// follows the edit.
	time.Sleep(10 * time.Millisecond)
	makeJPEG(t, root, "photos/one.jpg", 700, 900)
	if _, err := f.Thumbnail(u, "/photos/one.jpg"); err != nil {
		t.Fatalf("second Thumbnail: %v", err)
	}
	after, _ = os.ReadDir(cache)
	if len(after) != 2 {
		t.Fatalf("cache holds %d files after an edit, want 2", len(after))
	}

	// A same-version repeat is the hit path: nothing new is written.
	if _, err := f.Thumbnail(u, "/photos/one.jpg"); err != nil {
		t.Fatalf("cached Thumbnail: %v", err)
	}
	after, _ = os.ReadDir(cache)
	if len(after) != 2 {
		t.Fatalf("a cached hit must not grow the cache; holds %d", len(after))
	}
}

func TestThumbnailRejectsNonImages(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	if err := f.SetThumbCache(t.TempDir()); err != nil {
		t.Fatalf("SetThumbCache: %v", err)
	}
	writeFile(t, root, "docs/note.txt", "just text")
	// And a file whose extension lies about its contents.
	writeFile(t, root, "photos/liar.png", "<html>this is not an image</html>")
	u := user(auth.AccessAdmin)

	if _, err := f.Thumbnail(u, "/docs/note.txt"); !errors.Is(err, ErrNotImage) {
		t.Errorf("txt: %v, want ErrNotImage", err)
	}
	if _, err := f.Thumbnail(u, "/photos/liar.png"); !errors.Is(err, ErrNotImage) {
		t.Errorf("corrupt png: %v, want ErrNotImage", err)
	}
	if _, err := f.Thumbnail(u, "/docs"); !errors.Is(err, ErrNotDir) {
		t.Errorf("directory: %v, want ErrNotDir", err)
	}
}

func TestThumbnailAccessChecks(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	if err := f.SetThumbCache(t.TempDir()); err != nil {
		t.Fatalf("SetThumbCache: %v", err)
	}
	makeJPEG(t, root, "photos/secret.jpg", 50, 50)
	// Built by hand: no root-level grant, so nothing but /docs is reachable.
	denied := &auth.User{Username: "u", Grants: []auth.Grant{
		{Path: "/docs", Level: auth.AccessRead},
	}}

	if _, err := f.Thumbnail(denied, "/photos/secret.jpg"); !errors.Is(err, ErrForbidden) {
		t.Errorf("denied: %v, want ErrForbidden", err)
	}
	if _, err := f.Thumbnail(user(auth.AccessAdmin), "/photos/nope.png"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v, want os.ErrNotExist", err)
	}
}

func TestThumbnailWorksWithoutCache(t *testing.T) {
	f := newTestFS(t)
	root := mustRoot(f)
	makeJPEG(t, root, "photos/ok.jpg", 500, 400)
	u := user(auth.AccessAdmin)

	thumb, err := f.Thumbnail(u, "/photos/ok.jpg")
	if err != nil {
		t.Fatalf("Thumbnail without a cache: %v", err)
	}
	if _, _, err := image.Decode(bytes.NewReader(thumb.Data)); err != nil {
		t.Fatalf("decode: %v", err)
	}
}
