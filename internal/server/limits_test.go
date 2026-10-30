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
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestBulkJobsDoNotStarveThumbnails: with every bulk slot taken (zips on
// slow phones, a big copy), interactive work still gets through.
func TestBulkJobsDoNotStarveThumbnails(t *testing.T) {
	h := newHarness(t)
	c := h.login("admin", "password123")
	for i := 0; i < cap(h.srv.bulkGate); i++ {
		h.srv.bulkGate <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < cap(h.srv.bulkGate); i++ {
			<-h.srv.bulkGate
		}
	})

	done := make(chan int, 1)
	go func() {
		resp, err := c.Get(h.server.URL + "/api/fs/thumb?path=/photos/b.png")
		if err != nil {
			done <- -1
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	select {
	case code := <-done:
		if code < 0 {
			t.Fatal("thumbnail request failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("thumbnail queued behind bulk jobs")
	}
}

// TestQueuedRequestLeavesWithItsClient: a request waiting for a slot gives
// up when its client goes away, instead of keeping a place in the queue.
func TestQueuedRequestLeavesWithItsClient(t *testing.T) {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)

	got := make(chan bool, 1)
	go func() {
		_, ok := takeSlot(r, gate)
		got <- ok
	}()
	cancel()
	select {
	case ok := <-got:
		if ok {
			t.Fatal("takeSlot succeeded on a full gate")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("takeSlot ignored the cancelled request")
	}
	if len(gate) != 1 {
		t.Fatalf("gate holds %d tokens, want only the original one", len(gate))
	}
}

// TestStalledZipIsCutOff: a zip whose reader stops reading gives its bulk
// slot back once stallLimit passes, rather than holding it forever.
func TestStalledZipIsCutOff(t *testing.T) {
	old := stallLimit
	stallLimit = 300 * time.Millisecond
	t.Cleanup(func() { stallLimit = old })

	h := newHarness(t)
	// Incompressible and larger than the socket buffers, so the server
	// blocks on a write while the client sits idle.
	big := make([]byte, 32<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	mkdir(t, h.root, "videos")
	write(t, h.root, "videos/v.bin", string(big))
	c := h.login("admin", "password123")

	resp, err := c.Get(h.server.URL + "/api/fs/zip?path=/videos")
	if err != nil {
		t.Fatalf("GET zip: %v", err)
	}
	defer resp.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	for len(h.srv.bulkGate) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("stalled zip still holds its bulk slot")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n, _ := io.Copy(io.Discard, resp.Body); n >= int64(len(big)) {
		t.Fatalf("stalled stream delivered %d bytes, want it cut short", n)
	}
}

// TestPasswordChangeIsThrottled: wrong current passwords are limited per
// account, so a stolen cookie is no free oracle for the password.
func TestPasswordChangeIsThrottled(t *testing.T) {
	h := newHarness(t)
	c := h.login("admin", "password123")
	body := `{"current_password":"wrong-guess","new_password":"another-password"}`

	for i := 0; i < 8; i++ {
		resp := h.post(c, "/api/auth/password", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("attempt %d: status %d, want 403", i+1, resp.StatusCode)
		}
	}
	resp := h.post(c, "/api/auth/password", body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("ninth attempt: status %d, want 429", resp.StatusCode)
	}
}
