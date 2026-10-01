//go:build windows

package cli

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal turns on ANSI escape sequence processing for the
// console behind w. It returns false when the console does not support it,
// in which case colors are disabled.
func enableVirtualTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
