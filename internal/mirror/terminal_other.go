//go:build !unix

package mirror

import "os"

func terminalWidth(f *os.File) int { return 0 }
