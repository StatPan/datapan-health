//go:build linux

package health

import (
	"os/exec"
	"syscall"
)

// configureBoundedObservationProcess puts the command in its own process
// group. This makes the deadline boundary cover shell-like descendants too,
// even though shell interpreters themselves are rejected by validation.
func configureBoundedObservationProcess(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func supportsBoundedObservationProcess() bool { return true }

func terminateBoundedObservationProcess(command *exec.Cmd) {
	if command.Process == nil {
		return
	}
	// Negative PID targets the isolated group. Process.Kill is retained as a
	// narrow fallback if group setup failed after command start.
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	_ = command.Process.Kill()
}
