package main

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// The long-lived sandbox has no shell and no control socket. Each CLI command
// runs as a separate foreground child; closing docker exec's stdin on cancel
// terminates that child before the host reports cancellation.
func main() {
	if len(os.Args) == 2 && os.Args[1] == "pause" {
		pauseUntilStopped(nil)
		return
	}
	if len(os.Args) < 3 || os.Args[1] != "run" {
		os.Exit(125)
	}
	command := exec.Command(os.Args[2], os.Args[3:]...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		os.Exit(125)
	}
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		_ = command.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		<-timer.C
		_ = command.Process.Kill()
	}()
	if err := command.Wait(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		os.Exit(125)
	}
}

func pauseUntilStopped(ready func()) {
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGTERM, syscall.SIGINT)
	if ready != nil {
		ready()
	}
	<-stopped
	signal.Stop(stopped)
}
