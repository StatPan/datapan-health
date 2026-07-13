// Package schemas validates repository-pinned external contracts.
package schemas

import (
	_ "embed"
	"encoding/json"
	"errors"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed datapan.health-probe.v1.schema.json
var healthProbeSchema []byte

var (
	healthProbeOnce sync.Once
	healthProbe     *jsonschema.Schema
	healthProbeErr  error
)

func ValidateHealthProbeV1(data []byte) error {
	healthProbeOnce.Do(func() {
		var document any
		if err := json.Unmarshal(healthProbeSchema, &document); err != nil {
			healthProbeErr = err
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.AssertFormat()
		if err := compiler.AddResource("https://schemas.datapan.dev/datapan.health-probe.v1.schema.json", document); err != nil {
			healthProbeErr = err
			return
		}
		healthProbe, healthProbeErr = compiler.Compile("https://schemas.datapan.dev/datapan.health-probe.v1.schema.json")
	})
	if healthProbeErr != nil {
		return healthProbeErr
	}
	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return errors.New("receipt is not valid JSON")
	}
	if err := healthProbe.Validate(instance); err != nil {
		return errors.New("receipt does not match datapan.health-probe.v1")
	}
	return nil
}
