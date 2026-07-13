package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const SchemaVersion = "datapan.health-probe.v1"

var allowedErrorClasses = map[string]bool{
	"": true, "availability": true, "authentication": true, "rate_limit": true,
	"timeout": true, "upstream_contract": true, "unknown": true,
}

type Receipt struct {
	SchemaVersion string    `json:"schema_version"`
	ProbeID       string    `json:"probe_id"`
	ObservedAt    time.Time `json:"observed_at"`
	Status        string    `json:"status"`
	DurationMS    int64     `json:"duration_ms"`
	ErrorClass    string    `json:"error_class,omitempty"`
}

func ReadReceipt(path string) (Receipt, error) {
	f, err := os.Open(path)
	if err != nil {
		return Receipt{}, err
	}
	defer f.Close()
	return DecodeReceipt(f)
}

func DecodeReceipt(r io.Reader) (Receipt, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
	if err != nil {
		return Receipt{}, err
	}
	if len(data) > 64*1024 {
		return Receipt{}, errors.New("receipt exceeds 64 KiB")
	}
	var receipt Receipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("invalid receipt: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Receipt{}, err
	}
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("receipt must contain exactly one JSON object")
	}
	return nil
}

func (r Receipt) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", r.SchemaVersion)
	}
	if r.ProbeID == "" || len(r.ProbeID) > 80 || strings.ContainsAny(r.ProbeID, " /_.,#+&?") {
		return errors.New("probe_id must be a safe Gatus endpoint key segment")
	}
	if r.ObservedAt.IsZero() {
		return errors.New("observed_at is required")
	}
	if r.Status != "healthy" && r.Status != "unhealthy" {
		return errors.New("status must be healthy or unhealthy")
	}
	if r.DurationMS < 0 || r.DurationMS > int64((24*time.Hour)/time.Millisecond) {
		return errors.New("duration_ms is outside the allowed range")
	}
	if !allowedErrorClasses[r.ErrorClass] {
		return errors.New("error_class is not public-safe")
	}
	if r.Status == "healthy" && r.ErrorClass != "" {
		return errors.New("healthy receipt cannot include error_class")
	}
	if r.Status == "unhealthy" && r.ErrorClass == "" {
		return errors.New("unhealthy receipt requires a public error_class")
	}
	return nil
}
