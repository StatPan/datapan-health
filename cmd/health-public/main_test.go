package main

import "testing"

func TestOperationReadModelConfigurationRequiresAllPinnedInputs(t *testing.T) {
	tests := []struct {
		name       string
		root       string
		pin        string
		store      string
		configured bool
		valid      bool
	}{
		{name: "not configured", configured: false, valid: true},
		{name: "root only", root: "/plan", configured: true, valid: false},
		{name: "pin only", pin: "/plan/pin.json", configured: true, valid: false},
		{name: "store only", store: "/attempts", configured: true, valid: false},
		{name: "root and pin", root: "/plan", pin: "/plan/pin.json", configured: true, valid: false},
		{name: "complete", root: "/plan", pin: "/plan/pin.json", store: "/attempts", configured: true, valid: true},
		{name: "whitespace is absent", root: "  ", pin: "\t", store: "", configured: false, valid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configured, valid := operationReadModelConfiguration(test.root, test.pin, test.store)
			if configured != test.configured || valid != test.valid {
				t.Fatalf("operationReadModelConfiguration() = (%t, %t), want (%t, %t)", configured, valid, test.configured, test.valid)
			}
		})
	}
}
