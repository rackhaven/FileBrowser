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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rackhaven/filebrowser/internal/auth"
	bfs "github.com/rackhaven/filebrowser/internal/fs"
)

// ------------------------------------------------------------ harness -----

type harness struct {
	t      *testing.T
	server *httptest.Server
	users  *auth.Store
	root   string
	client *http.Client
}

// newHarness builds a live server over a temporary root.
func newHarness(t *testing.T) *harness {
	t.Helper()

	root := t.TempDir()
	mkdir(t, root, "photos/2024")
	mkdir(t, root, "docs")
	write(t, root, "photos/2024/a.jpg", "JPEGDATA")
	write(t, root, "photos/b.png", "PNGDATA")
	write(t, root, "docs/notes.txt", "secret notes")

	users, err := auth.OpenStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := users.Create("admin", "password123", true, nil); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	files, err := bfs.New(root)
	if err != nil {
		t.Fatalf("New FS: %v", err)
	}

	srv := New(Options{
		Config:   Config{SessionTTL: time.Hour},
		Users:    users,
		Sessions: auth.NewSessions(time.Hour),
		FS:       files,
		Static:   testAssets(),
		Version:  "test",
		// Discard request logs: they bury test failures in noise.
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &harness{
		t:      t,
		server: ts,
		users:  users,
		root:   root,
		client: ts.Client(),
	}
}

// testAssets serves a minimal in-memory stand-in for the real embedded PWA, so
// the handler tests do not depend on the build having run.
func testAssets() fstest.MapFS {
	return fstest.MapFS{
		"index.html":           {Data: []byte("<!doctype html><title>Files</title>")},
		"sw.js":                {Data: []byte("// service worker")},
		"manifest.webmanifest": {Data: []byte(`{"name":"Files"}`)},
		"styles.css":           {Data: []byte("/* styles */")},
		"app.js":               {Data: []byte("// app")},
	}
}

func mkdir(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(rel)), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(rel)), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// login signs in and returns a client that carries the session cookie.
func (h *harness) login(username, password string) *http.Client {
	h.t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		h.t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar}

	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)
	resp, err := client.Post(h.server.URL+"/api/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		h.t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("login %s: status %d: %s", username, resp.StatusCode, payload)
	}
	return client
}

func (h *harness) get(client *http.Client, path string) *http.Response {
	h.t.Helper()
	resp, err := client.Get(h.server.URL + path)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func (h *harness) post(client *http.Client, path, body string) *http.Response {
	h.t.Helper()
	resp, err := client.Post(h.server.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (h *harness) patch(client *http.Client, path, body string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest("PATCH", h.server.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatalf("PATCH %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatalf("PATCH %s: %v", path, err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// --------------------------------------------------------------- tests ----

func TestRequiresAuthentication(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/api/fs/list?path=/",
		"/api/auth/me",
		"/api/fs/download?path=/photos/b.png",
		"/api/admin/users",
	} {
		resp := h.get(h.client, path) // no cookie
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401", path, resp.StatusCode)
		}
	}
}

func TestLoginSetsSecureCookieShape(t *testing.T) {
	h := newHarness(t)

	resp, err := h.client.Post(h.server.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"password123"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	// httptest is plain HTTP, so Secure must be false here. It becomes true
	// only when the request is known to be over TLS.
	if cookie.Secure {
		t.Error("Secure should be false for a plain HTTP request")
	}
}

func TestSecureCookieBehindTrustedProxy(t *testing.T) {
	h := newHarness(t)

	// With proxy trust off, X-Forwarded-Proto must be ignored.
	req, _ := http.NewRequest("POST", h.server.URL+"/api/auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Secure {
			t.Error("X-Forwarded-Proto must not be trusted unless configured")
		}
	}
}

func TestBadLoginRejected(t *testing.T) {
	h := newHarness(t)

	for _, body := range []string{
		`{"username":"admin","password":"wrong"}`,
		`{"username":"nobody","password":"password123"}`,
	} {
		resp, err := h.client.Post(h.server.URL+"/api/auth/login", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		payload := decode(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", resp.StatusCode)
		}
		// Identical message either way, so accounts cannot be enumerated.
		if payload["error"] != "incorrect username or password" {
			t.Errorf("error = %v", payload["error"])
		}
	}
}

func TestLoginRateLimited(t *testing.T) {
	h := newHarness(t)

	// The limiter allows 8 attempts per IP, then refuses.
	var last int
	for i := 0; i < 12; i++ {
		resp, err := h.client.Post(h.server.URL+"/api/auth/login", "application/json",
			strings.NewReader(`{"username":"admin","password":"wrong"}`))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		last = resp.StatusCode
		resp.Body.Close()
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after 12 attempts the last status was %d, want 429", last)
	}
}

func TestListAsAdmin(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	resp := h.get(client, "/api/fs/list?path=/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body := decode(t, resp)

	entries, _ := body["entries"].([]any)
	names := map[string]bool{}
	for _, e := range entries {
		m := e.(map[string]any)
		names[m["name"].(string)] = true
	}
	for _, want := range []string{"photos", "docs"} {
		if !names[want] {
			t.Errorf("listing is missing %q", want)
		}
	}
	if body["can_write"] != true {
		t.Error("an admin should have write access")
	}
}

func TestPerUserGrantsAreEnforced(t *testing.T) {
	h := newHarness(t)

	if _, err := h.users.Create("alice", "password123", false, []auth.Grant{
		{Path: "/photos", Level: auth.AccessRead},
	}); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	client := h.login("alice", "password123")

	// Granted folder works.
	resp := h.get(client, "/api/fs/list?path=/photos")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing /photos = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Ungranted folder does not.
	resp = h.get(client, "/api/fs/list?path=/docs")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("listing /docs = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// The root listing must not reveal the ungranted folder's name.
	resp = h.get(client, "/api/fs/list?path=/")
	body := decode(t, resp)
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "docs") {
		t.Errorf("root listing leaked an ungranted folder: %s", raw)
	}
}

func TestDownloadWithinRootOnly(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	resp := h.get(client, "/api/fs/download?path=/photos/b.png")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download = %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "PNGDATA" {
		t.Fatalf("content = %q", data)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
}

func TestDownloadTraversalBlocked(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	// These are all virtual paths; ".." must clamp to the root, never escape.
	for _, path := range []string{
		"/api/fs/download?path=/../../../etc/passwd",
		"/api/fs/download?path=/..%2f..%2f..%2fetc%2fpasswd",
		`/api/fs/download?path=\..\..\windows\win.ini`,
	} {
		resp := h.get(client, path)
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(body), "root:") || strings.Contains(string(body), "[fonts]") {
				t.Fatalf("%s leaked a file outside the root", path)
			}
		}
		resp.Body.Close()
	}
}

func TestRangeRequestResumesDownload(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	req, _ := http.NewRequest("GET", h.server.URL+"/api/fs/download?path=/photos/b.png", nil)
	req.Header.Set("Range", "bytes=4-")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("range request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status %d, want 206", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	// The file is "PNGDATA"; bytes 4.. are "ATA".
	if string(data) != "ATA" {
		t.Fatalf("partial content = %q, want %q", data, "ATA")
	}
}

func TestNonAdminCannotManageUsers(t *testing.T) {
	h := newHarness(t)

	if _, err := h.users.Create("bob", "password123", false, nil); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	client := h.login("bob", "password123")

	resp := h.get(client, "/api/admin/users")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET /api/admin/users = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAdminCanCreateUserWithGrants(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	resp := h.post(client, "/api/admin/users",
		`{"username":"carol","password":"password123","admin":false,"grants":[{"path":"/docs","level":"read"}]}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d", resp.StatusCode)
	}
	body := decode(t, resp)
	if body["username"] != "carol" {
		t.Errorf("username = %v", body["username"])
	}

	// The new account must actually be limited to /docs.
	carol := h.login("carol", "password123")
	r := h.get(carol, "/api/fs/list?path=/photos")
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("carol reached /photos: %d", r.StatusCode)
	}
	r.Body.Close()
}

func TestGrantValidationRejectsTraversal(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	for _, body := range []string{
		`{"username":"x1","password":"password123","grants":[{"path":"../etc","level":"read"}]}`,
		`{"username":"x2","password":"password123","grants":[{"path":"/a/../../etc","level":"read"}]}`,
		`{"username":"x3","password":"password123","grants":[{"path":"relative","level":"read"}]}`,
	} {
		resp := h.post(client, "/api/admin/users", body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("grant %s = %d, want 400", body, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestBootstrapOnlyWorksWhenEmpty(t *testing.T) {
	h := newHarness(t)

	// The instance already has an admin, so bootstrap must be refused.
	resp := h.post(h.client, "/api/auth/bootstrap",
		`{"username":"attacker","password":"password123"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("bootstrap on a set-up instance = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestBootstrapCreatesFirstAdmin(t *testing.T) {
	root := t.TempDir()
	users, err := auth.OpenStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	files, err := bfs.New(root)
	if err != nil {
		t.Fatalf("New FS: %v", err)
	}
	srv := New(Options{
		Config:  Config{SessionTTL: time.Hour},
		Users:   users,
		FS:      files,
		Static:  testAssets(),
		Version: "test",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := ts.Client().Post(ts.URL+"/api/auth/bootstrap", "application/json",
		strings.NewReader(`{"username":"firstadmin","password":"password123"}`))
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap = %d, want 201", resp.StatusCode)
	}

	// It must be an administrator.
	u, err := users.GetByUsername("firstadmin")
	if err != nil {
		t.Fatalf("user missing: %v", err)
	}
	if !u.Admin {
		t.Error("the bootstrapped user should be an admin")
	}
}

func TestWriteOperationsRequireWriteGrant(t *testing.T) {
	h := newHarness(t)

	if _, err := h.users.Create("reader", "password123", false, []auth.Grant{
		{Path: "/photos", Level: auth.AccessRead},
	}); err != nil {
		t.Fatalf("create reader: %v", err)
	}
	client := h.login("reader", "password123")

	resp := h.post(client, "/api/fs/mkdir", `{"path":"/photos","name":"nope"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("mkdir with a read grant = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.post(client, "/api/fs/delete?path=/photos/b.png", `{}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("delete with a read grant = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestMkdirWorks(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	resp := h.post(client, "/api/fs/mkdir", `{"path":"/photos","name":"newfolder"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mkdir = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	if _, err := os.Stat(filepath.Join(h.root, "photos", "newfolder")); err != nil {
		t.Fatalf("folder not created on disk: %v", err)
	}
}

func TestUploadWritesFile(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	url := fmt.Sprintf("%s/api/fs/upload?path=%s&name=%s",
		h.server.URL, "/photos", "uploaded.txt")
	req, _ := http.NewRequest("PUT", url, bytes.NewReader([]byte("uploaded content")))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d", resp.StatusCode)
	}

	data, err := os.ReadFile(filepath.Join(h.root, "photos", "uploaded.txt"))
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	if string(data) != "uploaded content" {
		t.Errorf("content = %q", data)
	}
}

func TestUploadRejectsTraversalFilename(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	url := h.server.URL + "/api/fs/upload?path=%2Fphotos&name=..%2F..%2Fescaped.txt"
	req, _ := http.NewRequest("PUT", url, strings.NewReader("nope"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("a filename containing traversal must be rejected")
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	resp := h.post(client, "/api/auth/logout", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// The old token must be dead immediately, not merely cookie-cleared.
	r := h.get(client, "/api/fs/list?path=/")
	if r.StatusCode != http.StatusUnauthorized {
		t.Errorf("after logout, list = %d, want 401", r.StatusCode)
	}
	r.Body.Close()
}

func TestDisabledUserSessionDies(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	u, _ := h.users.GetByUsername("admin")
	resp := h.patch(client, fmt.Sprintf("/api/admin/users/%s", u.ID), `{"disabled":true}`)
	if resp.StatusCode != http.StatusConflict {
		// 409: the request is well-formed but conflicts with the current state.
		t.Fatalf("disabling the only admin = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	// With two admins the second can be disabled, and its session must die.
	if _, err := h.users.Create("admin2", "password123", true, nil); err != nil {
		t.Fatalf("create admin2: %v", err)
	}
	admin2 := h.login("admin2", "password123")
	other, _ := h.users.GetByUsername("admin2")

	resp = h.patch(client, fmt.Sprintf("/api/admin/users/%s", other.ID), `{"disabled":true}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disabling admin2 = %d", resp.StatusCode)
	}
	resp.Body.Close()

	r := h.get(admin2, "/api/fs/list?path=/")
	if r.StatusCode != http.StatusUnauthorized {
		t.Errorf("a disabled user's session should stop working, got %d", r.StatusCode)
	}
	r.Body.Close()
}

func TestSecurityHeadersPresent(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	resp := h.get(client, "/api/fs/list?path=/")
	defer resp.Body.Close()

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "same-origin",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP looks wrong: %q", csp)
	}
}

func TestShellIsServedWithoutAuth(t *testing.T) {
	h := newHarness(t)

	// The PWA shell must load so the login form can render.
	resp := h.get(h.client, "/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<title>") {
		t.Error("the shell should be HTML")
	}
}

func TestAPIReturnsJSONNotHTML(t *testing.T) {
	h := newHarness(t)

	resp := h.get(h.client, "/api/nonexistent")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
}

func TestChangePassword(t *testing.T) {
	h := newHarness(t)

	if _, err := h.users.Create("dave", "password123", false, nil); err != nil {
		t.Fatalf("create dave: %v", err)
	}
	client := h.login("dave", "password123")

	// Wrong current password is refused.
	resp := h.post(client, "/api/auth/password",
		`{"current_password":"nope","new_password":"newpassword1"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.post(client, "/api/auth/password",
		`{"current_password":"password123","new_password":"newpassword1"}`)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// The new password works.
	h.login("dave", "newpassword1")
}

func TestUsageReportsTotals(t *testing.T) {
	h := newHarness(t)
	client := h.login("admin", "password123")

	resp := h.get(client, "/api/fs/usage?path=/&depth=8")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("usage = %d", resp.StatusCode)
	}
	body := decode(t, resp)

	files, _ := body["files"].(float64)
	if files != 3 {
		t.Errorf("files = %v, want 3 (a.jpg, b.png, notes.txt)", body["files"])
	}
	wantBytes := float64(len("JPEGDATA") + len("PNGDATA") + len("secret notes"))
	if body["bytes"] != wantBytes {
		t.Errorf("bytes = %v, want %v", body["bytes"], wantBytes)
	}
}
