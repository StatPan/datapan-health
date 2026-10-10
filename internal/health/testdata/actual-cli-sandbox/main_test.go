package main

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestPauseSupervisorStopsOnTerminationSignal(t *testing.T) {
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		pauseUntilStopped(func() { close(ready) })
		close(done)
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("pause supervisor did not register its stop signal")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal("could not send the fixture stop signal")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pause supervisor did not exit on the stop signal")
	}
}
