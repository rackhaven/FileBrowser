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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readFromWriter is a ResponseWriter that, like net/http's own, can take a
// whole reader at once, and records that it was asked to.
type readFromWriter struct {
	*httptest.ResponseRecorder
	readFromCalls int
}

func (w *readFromWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFromCalls++
	return io.Copy(w.ResponseRecorder, r)
}

// TestStatusRecorderKeepsReadFrom: the logging wrapper must not hide the
// writer's ReadFrom, or downloads lose sendfile and copy through userspace.
// The status it logs must survive the shortcut too.
func TestStatusRecorderKeepsReadFrom(t *testing.T) {
	under := &readFromWriter{ResponseRecorder: httptest.NewRecorder()}
	rec := &statusRecorder{ResponseWriter: under, status: http.StatusOK}

	rec.WriteHeader(http.StatusPartialContent)
	// What http.ServeContent does with the file: CopyN, i.e. a LimitedReader,
	// which only a ReadFrom on the destination can short-cut.
	n, err := io.CopyN(rec, strings.NewReader("0123456789"), 4)
	if err != nil || n != 4 {
		t.Fatalf("CopyN = %d, %v", n, err)
	}
	if under.readFromCalls != 1 {
		t.Fatalf("underlying ReadFrom called %d times, want 1", under.readFromCalls)
	}
	if got := under.Body.String(); got != "0123" {
		t.Fatalf("body = %q", got)
	}
	if rec.status != http.StatusPartialContent {
		t.Fatalf("logged status = %d, want 206", rec.status)
	}

	// A writer without ReadFrom still gets every byte.
	plain := httptest.NewRecorder()
	rec = &statusRecorder{ResponseWriter: plain, status: http.StatusOK}
	if _, err := io.CopyN(rec, strings.NewReader("abcdef"), 6); err != nil || plain.Body.String() != "abcdef" {
		t.Fatalf("fallback copy = %q, %v", plain.Body.String(), err)
	}
}

// TestHandlersSeeReadFrom: through the logging middleware, the writer a
// handler receives still offers ReadFrom when the server's writer does.
func TestHandlersSeeReadFrom(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var offered bool
	h := s.requestLogger(securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, offered = w.(io.ReaderFrom)
	})))
	h.ServeHTTP(&readFromWriter{ResponseRecorder: httptest.NewRecorder()}, httptest.NewRequest(http.MethodGet, "/api/fs/download", nil))
	if !offered {
		t.Fatal("the handler's writer hides ReadFrom")
	}
}

// BenchmarkDownload streams a file through the whole handler stack over
// loopback; with sendfile engaged it should run well past the plain copy
// loop. Run with: go test ./internal/server -run '^$' -bench Download
func BenchmarkDownload(b *testing.B) {
	h := newHarness(b)
	const size = 256 << 20
	f, err := os.Create(filepath.Join(h.root, "big.bin"))
	if err != nil {
		b.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		b.Fatal(err)
	}
	f.Close()
	c := h.login("admin", "password123")

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := c.Get(h.server.URL + "/api/fs/download?path=/big.bin")
		if err != nil {
			b.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if n != size {
			b.Fatalf("got %d bytes", n)
		}
	}
}
