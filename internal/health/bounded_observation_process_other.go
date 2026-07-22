//go:build !linux

package health

import (
	"errors"
	"os/exec"
)

// This runner is deliberately fail-closed until each supported platform has a
// verified whole-process-tree termination primitive.
func configureBoundedObservationProcess(_ *exec.Cmd) error {
	return errors.New("bounded observation runner is unsupported on this platform")
}

func supportsBoundedObservationProcess() bool { return false }

func terminateBoundedObservationProcess(_ *exec.Cmd) {}
