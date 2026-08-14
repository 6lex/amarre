package fleet

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

func asExitError(err error, target **ssh.ExitError) bool {
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		*target = ee
		return true
	}
	return false
}
