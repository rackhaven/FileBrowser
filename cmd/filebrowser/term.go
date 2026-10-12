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

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// stdin is shared across readLine calls. A bufio.Reader may read ahead, so a
// fresh reader per call would swallow the rest of a piped password: the first
// ReadString would buffer both lines and the second would see EOF.
var (
	stdinMu sync.Mutex
	stdin   *bufio.Reader
)

// readLine reads one line, with echo disabled when stdin is a terminal so a
// password is never painted on screen or left in scrollback. When stdin is a
// pipe it falls back to a plain read, which is what makes the CLI usable from
// a provisioning script.
func readLine() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("could not read input: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}

	stdinMu.Lock()
	defer stdinMu.Unlock()

	if stdin == nil {
		stdin = bufio.NewReader(os.Stdin)
	}

	line, err := stdin.ReadString('\n')
	if err != nil && errors.Is(err, os.ErrClosed) {
		return "", errors.New("no input available")
	}
	// err == io.EOF with a non-empty line is the normal "last line, no trailing
	// newline" case, so only treat a genuinely empty read as a failure.
	if err != nil && line == "" {
		return "", fmt.Errorf("could not read input: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
