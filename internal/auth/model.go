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

package auth

import (
	"fmt"
	"strings"
	"time"
)

// AccessLevel is the permission a user holds on a folder.
type AccessLevel int

const (
	// AccessNone means no access at all.
	AccessNone AccessLevel = iota
	// AccessRead allows listing a folder and downloading from it.
	AccessRead
	// AccessWrite allows AccessRead plus upload, rename and delete.
	AccessWrite
	// AccessAdmin allows everything AccessWrite does, plus changing the ACL
	// of subfolders.
	AccessAdmin
)

var levelNames = map[AccessLevel]string{
	AccessNone:  "none",
	AccessRead:  "read",
	AccessWrite: "write",
	AccessAdmin: "admin",
}

func (l AccessLevel) String() string {
	if s, ok := levelNames[l]; ok {
		return s
	}
	return "none"
}

// MarshalText lets AccessLevel round-trip through JSON as a readable string.
func (l AccessLevel) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

// UnmarshalText parses the string form produced by MarshalText.
func (l *AccessLevel) UnmarshalText(b []byte) error {
	parsed, err := ParseLevel(string(b))
	if err != nil {
		return err
	}
	*l = parsed
	return nil
}

// ParseLevel converts user input into an AccessLevel.
func ParseLevel(s string) (AccessLevel, error) {
	switch s {
	case "", "none":
		return AccessNone, nil
	case "read", "r":
		return AccessRead, nil
	case "write", "w":
		return AccessWrite, nil
	case "admin", "a":
		return AccessAdmin, nil
	}
	return AccessNone, fmt.Errorf("auth: unknown access level %q", s)
}

// Grant is a rule giving a user a level of access to a folder and everything
// beneath it. Path is always virtual and slash-separated, starting with "/".
type Grant struct {
	Path  string      `json:"path"`
	Level AccessLevel `json:"level"`
}

// User is a stored account.
type User struct {
	ID                 string    `json:"id"`
	Username           string    `json:"username"`
	PasswordHash       string    `json:"password_hash"`
	Admin              bool      `json:"admin"`
	Disabled           bool      `json:"disabled"`
	MustChangePassword bool      `json:"must_change_password"`
	Grants             []Grant   `json:"grants"`
	CreatedAt          time.Time `json:"created_at"`
}

// EffectiveLevel returns the strongest level the user holds on vpath. The
// longest matching grant wins, so a narrow write grant inside a broad read
// grant correctly upgrades just that subtree.
func (u *User) EffectiveLevel(vpath string) AccessLevel {
	if u == nil {
		return AccessNone
	}
	if u.Admin {
		return AccessAdmin
	}

	best := AccessNone
	bestLen := -1
	for _, g := range u.Grants {
		if !pathCovers(g.Path, vpath) {
			continue
		}
		// Longer, more specific grants win. Ties keep the stronger level.
		if n := len(g.Path); n > bestLen || (n == bestLen && g.Level > best) {
			best = g.Level
			bestLen = n
		}
	}
	return best
}

// pathCovers reports whether a grant rooted at prefix applies to p. Both are
// treated as absolute virtual paths. Matching is on whole segments, so a grant
// on "/docs" covers "/docs/a/b" but never "/docs-archive".
func pathCovers(prefix, p string) bool {
	prefix = normalizeVirtual(prefix)
	p = normalizeVirtual(p)
	if prefix == "/" {
		return true
	}
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// normalizeVirtual makes a virtual path absolute and strips trailing slashes,
// so "/photos/", "photos" and "//photos" all compare equal.
func normalizeVirtual(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	if p == "" {
		return "/"
	}
	return p
}

// HasAnyGrantUnder reports whether the user has a grant at p or anywhere
// beneath it. It lets a user who can only read /photos/private still browse
// into /photos to reach that folder, instead of the link being invisible.
func (u *User) HasAnyGrantUnder(p string) bool {
	if u == nil {
		return false
	}
	if u.Admin {
		return true
	}
	p = normalizeVirtual(p)
	for _, g := range u.Grants {
		if pathCovers(g.Path, p) || pathCovers(p, g.Path) {
			return true
		}
	}
	return false
}

// RestrictedBelow reports whether a grant strictly beneath p gives the user
// less than level. Operations that act on a whole subtree at once (delete,
// move, erase from the trash) consult it: holding write on a folder is not
// write on a narrower read-only rule inside it, and carrying that folder off
// would take the protected content with it.
func (u *User) RestrictedBelow(p string, level AccessLevel) bool {
	if u == nil {
		return true
	}
	if u.Admin {
		return false
	}
	p = normalizeVirtual(p)
	for _, g := range u.Grants {
		gp := normalizeVirtual(g.Path)
		if gp != p && pathCovers(p, gp) && g.Level < level {
			return true
		}
	}
	return false
}

// PublicUser is the JSON shape sent to clients. It never contains the hash.
type PublicUser struct {
	ID                 string    `json:"id"`
	Username           string    `json:"username"`
	Admin              bool      `json:"admin"`
	Disabled           bool      `json:"disabled"`
	MustChangePassword bool      `json:"must_change_password"`
	Grants             []Grant   `json:"grants"`
	CreatedAt          time.Time `json:"created_at"`
}

// Public strips the password hash for safe transmission.
func (u *User) Public() PublicUser {
	return PublicUser{
		ID:                 u.ID,
		Username:           u.Username,
		Admin:              u.Admin,
		Disabled:           u.Disabled,
		MustChangePassword: u.MustChangePassword,
		Grants:             u.Grants,
		CreatedAt:          u.CreatedAt,
	}
}
