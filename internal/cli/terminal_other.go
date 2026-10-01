//go:build !windows

package cli

import "io"

// enableVirtualTerminal is a no-op outside Windows, where terminals
// interpret ANSI escape sequences natively.
func enableVirtualTerminal(io.Writer) bool { return true }
