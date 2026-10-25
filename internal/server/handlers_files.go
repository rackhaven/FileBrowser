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

package server

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/rackhaven/filebrowser/internal/auth"
	"github.com/rackhaven/filebrowser/internal/fs"
)

// writeFSError maps filesystem errors onto HTTP responses. Callers get a
// consistent shape and never learn the real path on disk.
func (s *Server) writeFSError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, fs.ErrForbidden):
		writeError(w, http.StatusForbidden, "you do not have access to this folder")
	case errors.Is(err, fs.ErrReserved):
		writeError(w, http.StatusConflict, "that name is reserved by the server (a .trash directory, or a .upload- file while uploads are in flight)")
	case errors.Is(err, fs.ErrNotExist):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, fs.ErrNotDir):
		writeError(w, http.StatusBadRequest, "expected a file")
	case errors.Is(err, fs.ErrNotImage):
		writeError(w, http.StatusUnsupportedMediaType, "that file is not an image the server can preview")
	case errors.Is(err, os.ErrNotExist):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, os.ErrPermission):
		writeError(w, http.StatusForbidden, "permission denied by the operating system")
	case errors.Is(err, os.ErrExist):
		writeError(w, http.StatusConflict, "an item with that name already exists")
	default:
		s.logError("filesystem error", "path", r.URL.Query().Get("path"), "err", err)
		writeError(w, http.StatusInternalServerError, "could not complete the request")
	}
}

// maxListPage caps the limit parameter, so a hostile offset cannot be turned
// into an unbounded response by naming a huge limit.
const maxListPage = 1000

// listWindow reads the optional offset and limit parameters. Without a limit
// the full listing is returned, which keeps the old response shape for every
// existing caller.
func listWindow(r *http.Request) (offset, limit int) {
	q := r.URL.Query()
	offset, _ = strconv.Atoi(q.Get("offset"))
	limit, _ = strconv.Atoi(q.Get("limit"))
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		return 0, 0
	}
	if limit > maxListPage {
		limit = maxListPage
	}
	return offset, limit
}

// handleList returns the entries of a directory.
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	vpath := r.URL.Query().Get("path")

	entries, err := s.files.List(u, vpath)
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}

	total := len(entries)
	page := entries
	offset, limit := listWindow(r)
	more := false
	if limit > 0 {
		if offset < total {
			page = entries[offset:]
		} else {
			page = nil
		}
		if len(page) > limit {
			page = page[:limit]
			more = true
		}
	} else {
		offset = 0
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"path":      fs.Clean(vpath),
		"parent":    parentOf(fs.Clean(vpath), u),
		"entries":   page,
		"can_write": u.EffectiveLevel(fs.Clean(vpath)) >= auth.AccessWrite,
		"total":     total,
		"more":      more,
	})
}

// parentOf returns the path to navigate up to, or "" at a boundary the user
// may not leave.
func parentOf(p string, u *auth.User) string {
	if p == "/" {
		return ""
	}
	parent := path.Dir(p)
	if parent == "." {
		parent = "/"
	}
	if u.Admin {
		return parent
	}
	// Do not offer "up" past the root of the user's grants, otherwise they
	// tap into an empty folder with no way back.
	if u.HasAnyGrantUnder(parent) || u.EffectiveLevel(parent) >= auth.AccessRead {
		return parent
	}
	return ""
}

// handleInfo describes a single entry.
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	entry, err := s.files.Info(u, r.URL.Query().Get("path"))
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

// handleDownload streams a file.
//
// http.ServeContent handles Range, If-Modified-Since and partial responses, so
// resuming an interrupted large download works, and the mobile browser gets a
// correct Content-Length rather than an unbounded chunked body.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	vpath := r.URL.Query().Get("path")

	file, info, err := s.files.Open(u, vpath)
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}
	defer file.Close()

	entry, err := s.files.Info(u, vpath)
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", detectContentType(info.Name()))
	// The allowlist is the server's decision to make: a query parameter
	// alone does not turn an arbitrary uploaded file into origin-rendered
	// content for someone else's browser.
	w.Header().Set("Content-Disposition", contentDisposition(entry.Name, r.URL.Query().Get("inline") == "1" && canInline(entry.Name)))
	w.Header().Set("Accept-Ranges", "bytes")
	// Private: a shared proxy must not cache someone's files.
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")

	// HEAD must not send a body.
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		w.WriteHeader(http.StatusOK)
		return
	}

	s.logf("download", "user", u.Username, "file", entry.Name, "bytes", info.Size())
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

// canInline answers whether the browser may render this file in place of a
// downloaded one. The list is an allowlist of formats a browser displays
// without giving the page's script a server-origin foothold, because a
// download link is something a user clicks with their session cookie in
// their pocket: an uploaded HTML file or SVG served inline every time
// someone else clicks a shared link is stored page scripting by any other
// name, on another user's browser. Video, text and everything else gets the
// default download behaviour, no matter what the loading UI hoped for.
func canInline(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".pdf":
		return true
	}
	return false
}

// contentDisposition builds the header. The filename is passed both as ASCII
// (for old clients) and RFC 5987 UTF-8 (for everything current), and is
// quoted because it is attacker-influenced file content.
func contentDisposition(name string, inline bool) string {
	ascii := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)

	kind := "attachment"
	if inline {
		kind = "inline"
	}
	return fmt.Sprintf(`%s; filename="%s"; filename*=UTF-8''%s`, kind, ascii, urlEscape(name))
}

// urlEscape percent-encodes for the RFC 5987 filename* parameter.
func urlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// detectContentType prefers a type derived from the extension, falling back to
// sniffing. It never returns anything executable-inline for unknown types.
func detectContentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	// An extension-less file is usually text (configs, logs, scripts).
	if ext == "" {
		return "text/plain; charset=utf-8"
	}
	return "application/octet-stream"
}

// handleUpload receives a file body.
//
// The body is streamed straight to disk rather than buffered in memory, so a
// multi-gigabyte file uses constant RAM. Uploads land in a temp file first and
// are renamed into place, so an interrupted upload never leaves a truncated
// file that looks complete.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	q := r.URL.Query()
	name := q.Get("name")

	target, vpath, err := s.files.UploadTarget(u, q.Get("path"), name, q.Get("overwrite") != "")
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}

	tmp, err := os.CreateTemp(pathOfDir(target), ".upload-*")
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}
	tmpName := tmp.Name()
	// Any failure past this point must remove the temp file.
	defer os.Remove(tmpName) // no-op once the rename succeeds

	// Cap the body so a hostile client cannot fill the disk. The limit comes
	// from max_upload_bytes, which defaults to 32 GiB.
	written, err := io.Copy(tmp, http.MaxBytesReader(w, r.Body, s.maxUpload))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "file is too large")
			return
		}
		s.logError("upload failed", "path", vpath, "err", err)
		writeError(w, http.StatusInternalServerError, "upload failed")
		return
	}

	// Force a predictable, non-executable mode. 0644 regardless of what the
	// source mode looked like: uploads are never made executable, so an
	// uploaded .sh cannot be run by accident before anyone inspects it.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		s.logError("chmod upload", "err", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Rename will not clobber on Windows; remove first so replacing a
			// file works the same on every platform.
			if rerr := os.Remove(target); rerr == nil {
				err = os.Rename(tmpName, target)
			}
		}
		if err != nil {
			s.writeFSError(w, r, err)
			return
		}
	}

	s.logf("upload", "user", u.Username, "file", name, "bytes", written)
	writeJSON(w, http.StatusOK, map[string]any{
		"path": vpath,
		"name": name,
		"size": written,
	})
}

func pathOfDir(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i > 0 {
		return p[:i]
	}
	return "."
}

type mkdirRequest struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// handleMkdir creates a directory.
func (s *Server) handleMkdir(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	var req mkdirRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	entry, err := s.files.Mkdir(u, req.Path, strings.TrimSpace(req.Name))
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

// handleDelete removes a file or folder.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	vpath := r.URL.Query().Get("path")
	if err := s.files.Remove(u, vpath); err != nil {
		s.writeFSError(w, r, err)
		return
	}
	s.logf("delete", "user", u.Username, "path", vpath)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type renameRequest struct {
	From    string `json:"from"`
	ToDir   string `json:"to_dir"`
	NewName string `json:"new_name"`
	// Overwrite lets the caller replace an existing file at the
	// destination after it has confirmed with a human. Without it a name
	// collision answers 409 Conflict.
	Overwrite bool `json:"overwrite"`
}

// handleRename moves or renames an entry.
func (s *Server) handleRename(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	var req renameRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	entry, err := s.files.Rename(u, req.From, req.ToDir, strings.TrimSpace(req.NewName), req.Overwrite)
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

// handleUsage returns storage totals for a folder, shown on the dashboard.
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	depth, _ := strconv.Atoi(r.URL.Query().Get("depth"))
	if depth <= 0 || depth > 16 {
		depth = 8
	}
	// Counting is a walk of everything visible, so it takes a work slot
	// like its siblings.
	release := s.workSlot()
	defer release()
	usage, err := s.files.Usage(u, r.URL.Query().Get("path"), depth)
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, usage)
}

// handleSearch looks for names below a folder. The authority line mirrors
// the listing: only what the user may see is returned, so names are not an
// enumeration oracle for hidden files.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	q := r.URL.Query()

	// A recursive search races whole subtrees; the work gate keeps a
	// spirited typist from stacking an unbounded number of walks.
	release := s.workSlot()
	defer release()
	found, err := s.files.Search(u, q.Get("path"), q.Get("q"))
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":    fs.Clean(q.Get("path")),
		"query":   strings.TrimSpace(strings.ToLower(q.Get("q"))),
		"entries": found.Entries,
		"more":    found.More,
	})
}

// handleThumb returns a small preview of an image file, or a 304 for a
// client that already holds the current version.
//
// Previews are derived data, so the browser may keep one for a day while the
// weak ETag still lets it revalidate after a file changes.
func (s *Server) handleThumb(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	vpath := r.URL.Query().Get("path")

	// Decoding is the most expensive read on the server: a huge image
	// costs hundreds of megabytes of RAM per concurrent request, so the
	// work gate bounds how many run at once. Cache hits pay the wait too,
	// which is the honest bonus of a bounded queue: nobody skips it.
	release := s.workSlot()
	defer release()
	thumb, err := s.files.Thumbnail(u, vpath)
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}

	// Weak: the exact bytes of a re-encoded preview are not promised across
	// processes; what matters is that a fresh view of an unchanged file is
	// an acceptable substitute for the bytes already held.
	etag := `W/"` + strconv.FormatInt(thumb.ModTime.UnixNano(), 16) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "private, max-age=86400")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", thumb.ContentType)
	w.Header().Set("Cache-Control", "private, max-age=86400")
	w.Header().Set("ETag", etag)
	_, _ = w.Write(thumb.Data)
}

// handleZip streams a folder as a zip archive. Streaming keeps memory flat,
// so no Content-Length is set: the archive's final size is not knowable in
// advance, which is also why the name comes from fs.ZipInfo so header and
// archive agree before any body bytes are sent.
func (s *Server) handleZip(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	vpath := r.URL.Query().Get("path")

	// Archive walking is whole-tree work, so it shares the bounded work
	// gate before any bytes move.
	release := s.workSlot()
	defer release()
	name, err := s.files.ZipInfo(u, vpath)
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDisposition(name+".zip", false))
	// A folder of live files must never sit in a shared proxy cache; every
	// request walks afresh so renames and deletes are reflected immediately.
	w.Header().Set("Cache-Control", "private, no-store")

	if err := s.files.Zip(u, vpath, w); err != nil {
		// Headers may already be committed, so the only useful move is to cut
		// the stream rather than append a JSON error to a binary body.
		s.logError("zip failed", "path", fs.Clean(vpath), "err", err)
		return
	}
	s.logf("zip", "user", u.Username, "path", fs.Clean(vpath))
}

// handleHealth is for uptime checks and the Docker HEALTHCHECK.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// ------------------------------------------------------------ ----- trash ---

// handleTrashList returns the trash entries the caller may act on.
func (s *Server) handleTrashList(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	entries, err := s.files.TrashList(u)
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

type trashActionRequest struct {
	Name string `json:"name"`
}

// handleRestore moves a trashed entry back to where it came from.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	var req trashActionRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.files.RestoreTrash(u, req.Name); err != nil {
		s.writeFSError(w, r, err)
		return
	}
	s.logf("restore", "user", u.Username, "name", req.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTrashDelete permanently removes a trashed entry, or the whole trash
// when no name is given (admin only, and the one trash action with no undo).
func (s *Server) handleTrashDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	name := r.URL.Query().Get("name")
	if name == "" {
		if err := s.files.TrashPurge(u); err != nil {
			s.writeFSError(w, r, err)
			return
		}
		s.logf("trash purged", "user", u.Username)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if err := s.files.TrashDelete(u, name); err != nil {
		s.writeFSError(w, r, err)
		return
	}
	s.logf("trash deleted", "user", u.Username, "name", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type copyRequest struct {
	From  string `json:"from"`
	ToDir string `json:"to_dir"`
	Name  string `json:"name"`
}

// handleCopy duplicates an entry. An empty name copies under the source's
// own name, so a copy with no name and no destination would land on the
// source and refuses; the UI therefore proposes a distinct name. Anything
// already at the destination is never replaced, which is the behaviour
// upload and rename do not share.
func (s *Server) handleCopy(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())

	var req copyRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.From) == "" {
		writeError(w, http.StatusBadRequest, "missing source path")
		return
	}
	if req.ToDir == "" {
		req.ToDir = path.Dir(fs.Clean(req.From))
	}

	// Duplicating a folder is whole-tree streaming work; it queues behind
	// the other heavy handlers.
	release := s.workSlot()
	defer release()
	entry, err := s.files.Copy(u, req.From, req.ToDir, req.Name)
	if err != nil {
		s.writeFSError(w, r, err)
		return
	}
	s.logf("copy", "user", u.Username, "from", req.From, "to", entry.Path)
	writeJSON(w, http.StatusOK, entry)
}
