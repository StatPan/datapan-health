//go:build !linux

package health

import "testing"

func TestBoundedObservationProcessIsUnsupportedOffLinux(t *testing.T) {
	if supportsBoundedObservationProcess() {
		t.Fatal("unsupported platform was allowed to run bounded observations")
	}
}
