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

//go:build !windows

package auth

import "syscall"

// flock is used rather than a lock on users.json itself: users.json is
// replaced by rename on every save, which would strand the lock on a dead
// inode. The lock file's own file description lives with the process, so a
// crash releases it automatically.
func (s *Store) lockEx() error {
	return syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_EX)
}

func (s *Store) lockUn() error {
	return syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
}
