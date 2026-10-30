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
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pngHeader is the signature and IHDR chunk of an 8-bit RGBA PNG of w x h,
// which is all image.DecodeConfig reads. Built by hand for the same reason
// thumb_test.go embeds its fixtures: image/png must not be imported here.
func pngHeader(w, h uint32) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	chunk := make([]byte, 4+13)
	copy(chunk, "IHDR")
	binary.BigEndian.PutUint32(chunk[4:], w)
	binary.BigEndian.PutUint32(chunk[8:], h)
	chunk[12] = 8 // bit depth
	chunk[13] = 6 // colour type: RGBA
	_ = binary.Write(&b, binary.BigEndian, uint32(13))
	b.Write(chunk)
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(chunk))
	return b.Bytes()
}

// TestThumbnailRefusesDecompressionBombs: a header claiming a canvas whose
// decode would blow the memory budget is refused before any pixel is read.
func TestThumbnailRefusesDecompressionBombs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "bomb.png", string(pngHeader(30000, 30000)))
	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// (The image/png header reader already refuses dimensions too large to
	// multiply; TestDecodeCostNeverOverflows covers that arithmetic here.)
	for _, name := range []string{"/bomb.png"} {
		// These files hold no pixel data, so a decode would fail too; the
		// message proves the budget refused them before one was tried.
		_, err := f.Thumbnail(adminUser(), name)
		if !errors.Is(err, ErrNotImage) || !strings.Contains(err.Error(), "too large to preview") {
			t.Errorf("Thumbnail(%s) = %v, want a too-large ErrNotImage", name, err)
		}
	}
}

// TestThumbnailBoundsPassThrough: a small header is no promise about the
// file size, so a tiny image followed by megabytes of padding is re-encoded
// rather than handed back whole.
func TestThumbnailBoundsPassThrough(t *testing.T) {
	root := t.TempDir()
	small := makeJPEG(t, root, "padded.jpg", 64, 64)
	padded := append(append([]byte(nil), small...), make([]byte, thumbPassThroughMax+1)...)
	writeFile(t, root, "padded.jpg", string(padded))
	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	th, err := f.Thumbnail(adminUser(), "/padded.jpg")
	if err != nil {
		t.Fatalf("Thumbnail: %v", err)
	}
	if th.ContentType != "image/jpeg" || len(th.Data) > 64<<10 {
		t.Fatalf("got %s of %d bytes, want a small re-encoded JPEG", th.ContentType, len(th.Data))
	}
}

func TestDecodeCostNeverOverflows(t *testing.T) {
	huge := image.Config{Width: math.MaxInt32, Height: math.MaxInt32, ColorModel: color.RGBA64Model}
	if got := decodeCost(huge); got <= thumbDecodeBudget {
		t.Fatalf("decodeCost(huge) = %d, must exceed the budget", got)
	}
	photo := image.Config{Width: 8000, Height: 6000, ColorModel: color.YCbCrModel} // 48 MP
	if got := decodeCost(photo); got > thumbDecodeBudget {
		t.Fatalf("a 48 MP photo costs %d, must fit the budget", got)
	}
}

// TestWalksEndOnLinkLoops: links back up the tree must not make zip or
// search loop; each real folder is visited once.
func TestWalksEndOnLinkLoops(t *testing.T) {
	needSymlinks(t)
	root := t.TempDir()
	writeFile(t, root, "d/f.txt", "once")
	writeFile(t, root, "d/sub/g.txt", "once")
	for link, target := range map[string]string{"d/l1": ".", "d/l2": ".", "d/sub/up": ".."} {
		if err := os.Symlink(target, filepath.Join(root, filepath.FromSlash(link))); err != nil {
			t.Fatalf("symlink: %v", err)
		}
	}
	f, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	within := func(what string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { fn(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s still running after 5s: the walk is looping", what)
		}
	}

	var raw bytes.Buffer
	within("zip", func() {
		if err := f.Zip(adminUser(), "/d", &raw); err != nil {
			t.Errorf("Zip: %v", err)
		}
	})
	count := 0
	for _, n := range zipNames(t, raw.Bytes()) {
		if strings.HasSuffix(n, "/f.txt") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("f.txt archived %d times, want once", count)
	}

	within("search", func() {
		out, err := f.Search(adminUser(), "/d", "g.txt")
		if err != nil || len(out.Entries) != 1 {
			t.Errorf("Search = %+v, %v; want exactly one match", out.Entries, err)
		}
		if _, err := f.Search(adminUser(), "/d", "no-such-name"); err != nil {
			t.Errorf("Search: %v", err)
		}
	})
}
