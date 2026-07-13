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

//go:embed datapan.health-archive.v1.schema.json
var healthArchiveSchema []byte

var (
	healthProbeOnce   sync.Once
	healthProbe       *jsonschema.Schema
	healthProbeErr    error
	healthArchiveOnce sync.Once
	healthArchive     *jsonschema.Schema
	healthArchiveErr  error
)

func ValidateHealthProbeV1(data []byte) error {
	healthProbeOnce.Do(func() {
		healthProbe, healthProbeErr = compile(healthProbeSchema, "https://schemas.datapan.dev/datapan.health-probe.v1.schema.json")
	})
	return validate(data, healthProbe, healthProbeErr, "receipt")
}

// ValidateHealthArchiveV1 only accepts the intentionally minimized public
// observation projection. Detailed receipts never cross this boundary.
func ValidateHealthArchiveV1(data []byte) error {
	healthArchiveOnce.Do(func() {
		healthArchive, healthArchiveErr = compile(healthArchiveSchema, "https://schemas.datapan.dev/datapan.health-archive.v1.schema.json")
	})
	return validate(data, healthArchive, healthArchiveErr, "archive observation")
}

func compile(source []byte, uri string) (*jsonschema.Schema, error) {
	var document any
	if err := json.Unmarshal(source, &document); err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(uri, document); err != nil {
		return nil, err
	}
	return compiler.Compile(uri)
}

func validate(data []byte, schema *jsonschema.Schema, schemaErr error, kind string) error {
	if schemaErr != nil {
		return schemaErr
	}
	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return errors.New(kind + " is not valid JSON")
	}
	if err := schema.Validate(instance); err != nil {
		return errors.New(kind + " does not match its pinned schema")
	}
	return nil
}
