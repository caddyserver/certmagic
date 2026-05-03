//go:build unix

package filedescriptor

import (
	"golang.org/x/sys/unix"
)

var IsUnix = true

func Dup(fd int) (int, error) {
	return unix.Dup(fd)
}
