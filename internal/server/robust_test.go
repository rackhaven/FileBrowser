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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUploadDoesNotReplaceAFileThatAppearedMidStream: the "already exists"
// check runs when the request starts, but the name is only claimed when the
// body is done. A file that arrived in between must survive, and the late
// upload is refused with 409.
func TestUploadDoesNotReplaceAFileThatAppearedMidStream(t *testing.T) {
	h := newHarness(t)
	c := h.login("admin", "password123")

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPut, h.server.URL+"/api/fs/upload?path=/docs&name=report.txt", pr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *http.Response, 1)
	go func() {
		resp, err := c.Do(req)
		if err != nil {
			done <- nil
			return
		}
		done <- resp
	}()

	if _, err := pw.Write([]byte("late upload, first half")); err != nil {
		t.Fatal(err)
	}
	// The server is now streaming the body to its temp file.
	time.Sleep(200 * time.Millisecond)
	write(t, h.root, "docs/report.txt", "arrived first")
	_, _ = pw.Write([]byte(", second half"))
	pw.Close()

	resp := <-done
	if resp == nil {
		t.Fatal("upload request failed")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d, want 409", resp.StatusCode)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "docs/report.txt")); string(b) != "arrived first" {
		t.Fatalf("the earlier file was replaced: %q", b)
	}
	// And the refused upload's temp file is gone.
	des, _ := os.ReadDir(filepath.Join(h.root, "docs"))
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".upload-") {
			t.Fatalf("temporary %s left behind", de.Name())
		}
	}
}

func TestRateKeyGroupsIPv6By64(t *testing.T) {
	same := []string{"2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff"}
	if rateKey(same[0]) != rateKey(same[1]) {
		t.Errorf("one /64 gave two keys: %q, %q", rateKey(same[0]), rateKey(same[1]))
	}
	if rateKey("2001:db8:1:2::1") == rateKey("2001:db8:1:3::1") {
		t.Error("neighbouring /64s share a key")
	}
	for in, want := range map[string]string{
		"203.0.113.5":        "203.0.113.5",
		"::ffff:203.0.113.5": "203.0.113.5",
		"not-an-ip":          "not-an-ip",
	} {
		if got := rateKey(in); got != want {
			t.Errorf("rateKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRateLimiterPrunesIdleKeys: addresses that never reach the limit
// still leave the table once their window has passed.
func TestRateLimiterPrunesIdleKeys(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	rl := newRateLimiter(8, 15*time.Minute)
	rl.now = func() time.Time { return now }

	for i := 0; i < 10000; i++ {
		rl.allow(fmt.Sprintf("198.51.100.%d-%d", i%256, i))
	}
	now = now.Add(16 * time.Minute)
	rl.allow("192.0.2.1")
	if n := len(rl.hits); n != 1 {
		t.Fatalf("limiter holds %d keys after the window, want 1", n)
	}
}

// TestLoginLimitCoversAWholeIPv6Prefix: rotating through one /64 does not
// buy fresh attempts.
func TestLoginLimitCoversAWholeIPv6Prefix(t *testing.T) {
	h := newHarnessWithConfig(t, Config{SessionTTL: time.Hour, TrustProxyHeaders: true})
	try := func(addr string) int {
		req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/api/auth/login",
			strings.NewReader(`{"username":"admin","password":"wrong-password"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", addr)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 1; i <= 8; i++ {
		if code := try(fmt.Sprintf("2001:db8:aa:1::%x", i)); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, code)
		}
	}
	if code := try("2001:db8:aa:1::beef"); code != http.StatusTooManyRequests {
		t.Fatalf("a ninth address in the same /64: status %d, want 429", code)
	}
	if code := try("2001:db8:aa:2::1"); code != http.StatusUnauthorized {
		t.Fatalf("another /64: status %d, want 401", code)
	}
}
