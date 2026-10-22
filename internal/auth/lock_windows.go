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

//go:build windows

package auth

// Cross-process locking is not implemented on Windows: the in-process mutex
// still serialises writes within the server, and the documented workflow is
// to run CLI maintenance while the server is stopped. A Windows equivalent
// (LockFileEx) can slot in behind the same two functions.

func (s *Store) lockEx() error { return nil }

func (s *Store) lockUn() error { return nil }
