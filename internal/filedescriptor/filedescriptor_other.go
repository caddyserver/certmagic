//go:build !unix

package filedescriptor

import "fmt"

var IsUnix = false

func Dup(fd int) (int, error) {
	return 0, fmt.Errorf("File descriptor duplication is not supported on this platform")
}
