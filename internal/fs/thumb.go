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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// The three decoders image.Decode / image.DecodeConfig can pick from.
	// Without these registrations a served PNG would fail with "unknown
	// format" and surface as 415; test packages that import png or gif for
	// their own encoders happen to register them globally, which is exactly
	// the kind of difference a production build must not depend on.
	_ "image/gif"
	_ "image/png"

	"github.com/rackhaven/filebrowser/internal/auth"
)

// ThumbSize is the edge of the square every generated thumbnail fits inside.
// One fixed size keeps the cache, the ETags and the interface simple; a
// picture shrunk to 320 pixels is plenty for a list row on any screen.
const ThumbSize = 320

// ErrNotImage says the named file is not an image this build can preview
// (neither by extension nor by content).
var ErrNotImage = errors.New("fs: not a supported image")

// thumbFormats maps the extensions that decode to their content type. WebP
// and friends are absent because the standard library has no decoder for
// them; rows of other extensions simply keep their icon, so nothing breaks.
var thumbFormats = map[string]string{
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".png":  "image/png",
	".gif":  "image/gif",
}

// Thumb is one preview of one file.
type Thumb struct {
	// Data are the image bytes: a generated JPEG, or the untouched original
	// when the file is already small enough to serve as its own thumbnail.
	Data []byte
	// ContentType is image/jpeg for generated views, else the source's type.
	ContentType string
	// ModTime is the source's mtime, the basis for the response's ETag.
	ModTime time.Time
}

// SetThumbCache points the FS at a directory for generated previews. Calling
// it is optional: with no cache set, every thumbnail request re-derives its
// image from disk, which is correct but wasteful on the second view.
func (f *FS) SetThumbCache(dir string) error {
	if dir == "" {
		return errors.New("fs: thumbnail cache directory must not be empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("fs: abs thumbnail cache %s: %w", dir, err)
	}
	// 0700: the cache holds derived copies of otherwise private files and
	// must not be readable by other local accounts.
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return fmt.Errorf("fs: create thumbnail cache %s: %w", abs, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("fs: resolve thumbnail cache %s: %w", abs, err)
	}
	f.thumbCache = real
	return nil
}

// Thumbnail returns a small preview of the image at vpath, taking it from a
// disk cache when one is configured and this view was generated before.
//
// Access is the same full check a download gets: traversal and symlink
// containment through Resolve, then read access on the file itself. Images at
// or below ThumbSize pass through with their original bytes and type; larger
// ones are decoded, resampled to fit, and re-encoded as JPEG.
func (f *FS) Thumbnail(u *auth.User, vpath string) (Thumb, error) {
	vp := Clean(vpath)
	realPath, err := f.Resolve(u, vp, auth.AccessRead)
	if err != nil {
		return Thumb{}, err
	}
	info, err := os.Stat(realPath)
	if err != nil {
		return Thumb{}, err
	}
	if info.IsDir() {
		return Thumb{}, ErrNotDir
	}

	format, ok := thumbFormats[strings.ToLower(filepath.Ext(info.Name()))]
	if !ok {
		return Thumb{}, ErrNotImage
	}

	var cachePath string
	if f.thumbCache != "" {
		cachePath = f.thumbCachePath(realPath, info)
		// The key is a digest of identity, mtime and size, so a hit is by
		// construction a preview of this exact version of the file; editing
		// a photo abandons its old preview instead of serving it.
		if data, rerr := os.ReadFile(cachePath); rerr == nil {
			return Thumb{Data: data, ContentType: "image/jpeg", ModTime: info.ModTime()}, nil
		}
	}

	// DecodeConfig reads only the header, so the fit decision for a huge
	// file costs kilobytes, not megabytes.
	cfg, derr := f.decodeConfigFile(relFromVP(vp))
	if derr != nil {
		// A dot-png that is really an HTML error page must fail as "not an
		// image", not as a 500.
		return Thumb{}, addNotImage(derr)
	}
	if cfg.Width <= ThumbSize && cfg.Height <= ThumbSize {
		// Already small: the original is its own best preview. Passing the
		// bytes straight through avoids a pointless re-encode.
		fh, oerr := openInside(f.realRoot, relFromVP(vp), os.O_RDONLY, 0)
		if oerr != nil {
			return Thumb{}, oerr
		}
		raw, rerr := io.ReadAll(fh)
		cerr := fh.Close()
		if rerr != nil {
			return Thumb{}, rerr
		}
		if cerr != nil {
			return Thumb{}, cerr
		}
		return Thumb{Data: raw, ContentType: format, ModTime: info.ModTime()}, nil
	}

	img, derr := f.decodeFile(relFromVP(vp))
	if derr != nil {
		return Thumb{}, addNotImage(derr)
	}

	scaled := scaleToFit(img)
	var buf bytes.Buffer
	if encErr := jpeg.Encode(&buf, scaled, &jpeg.Options{Quality: 80}); encErr != nil {
		return Thumb{}, fmt.Errorf("fs: encode thumbnail: %w", encErr)
	}
	data := buf.Bytes()
	// Best effort: a cache write failure costs one re-encode next time,
	// nothing more. 0600 within the 0700 cache keeps other accounts out.
	if cachePath != "" {
		_ = os.WriteFile(cachePath, data, 0o600)
	}
	return Thumb{Data: data, ContentType: "image/jpeg", ModTime: info.ModTime()}, nil
}

// thumbCachePath is the cache file for one exact version of a file. Identity
// (a path is already unique inside the root), mtime and size are all mixed
// into the digest, so an edit produces a fresh key while an unchanged file
// keeps hitting the same one.
func (f *FS) thumbCachePath(realPath string, info os.FileInfo) string {
	sum := sha256.Sum256([]byte(realPath + "\x00" +
		strconv.FormatInt(info.ModTime().UnixNano(), 16) + "\x00" +
		strconv.FormatInt(info.Size(), 10)))
	return filepath.Join(f.thumbCache, "t-"+hex.EncodeToString(sum[:16])+".jpg")
}

// decodeConfigFile opens the image under the root (rel is the root-relative
// slash path) and asks the registered decoders how large the image inside is,
// without decoding the pixels.
func (f *FS) decodeConfigFile(rel string) (image.Config, error) {
	file, err := openInside(f.realRoot, rel, os.O_RDONLY, 0)
	if err != nil {
		return image.Config{}, err
	}
	defer file.Close()
	cfg, _, derr := image.DecodeConfig(file)
	if derr != nil {
		return image.Config{}, derr
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return image.Config{}, errors.New("image has no dimensions")
	}
	return cfg, nil
}

// decodeFile decodes the first frame of the image found under the root at rel.
func (f *FS) decodeFile(rel string) (image.Image, error) {
	file, err := openInside(f.realRoot, rel, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	img, _, derr := image.Decode(file)
	if derr != nil {
		return nil, derr
	}
	return img, nil
}

// addNotImage dresses a decode failure in ErrNotImage while keeping the
// original message for whoever ends up logging it.
func addNotImage(err error) error {
	return fmt.Errorf("%w (%v)", ErrNotImage, err)
}

// ThumbSweep carries out cache retention: generated previews older than
// maxAge are deleted so the cache cannot grow without end. Only files in
// the configured cache directory are touched, and the sweep treats the
// cache for what it is: derived data, always safe to delete.
func (f *FS) ThumbSweep(maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	if f.thumbCache == "" {
		return 0, nil
	}
	des, err := os.ReadDir(f.thumbCache)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}

	cutoff := time.Now().UTC().Add(-maxAge)
	removed := 0
	for _, de := range des {
		info, ierr := de.Info()
		if ierr != nil {
			continue // vanished mid-sweep: nothing to do about it
		}
		if !info.ModTime().UTC().Before(cutoff) {
			continue // young enough to keep
		}
		if err := os.Remove(filepath.Join(f.thumbCache, de.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
