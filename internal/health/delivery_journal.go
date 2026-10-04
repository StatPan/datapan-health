package health

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// DeliveryAcknowledgement is written only after Gatus accepted the summary.
// It retains original observation time without provider targets or rows.
type DeliveryAcknowledgement struct {
	SchemaVersion    string    `json:"schema_version"`
	ProbeID          string    `json:"probe_id"`
	OperationID      string    `json:"operation_id"`
	ObservedAt       time.Time `json:"observed_at"`
	AcceptedAt       time.Time `json:"accepted_at"`
	RegistryRevision string    `json:"registry_revision"`
	PublicReadback   string    `json:"public_readback"`
}

func StoreDeliveryAcknowledgement(path string, r Receipt, canary Canary) error {
	record := DeliveryAcknowledgement{SchemaVersion: "datapan.health-delivery-ack.v1", ProbeID: r.ProbeID, OperationID: canary.OperationID, ObservedAt: r.ObservedAt, AcceptedAt: time.Now().UTC(), RegistryRevision: r.Registry.DatasetRevision, PublicReadback: "not_checked"}
	raw, err := json.Marshal(record)
	if err != nil {
		return errors.New("delivery journal unavailable")
	}
	if os.MkdirAll(filepath.Dir(path), 0750) != nil {
		return errors.New("delivery journal unavailable")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return errors.New("delivery journal unavailable")
	}
	defer f.Close()
	raw = append(raw, '\n')
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		return errors.New("delivery journal unavailable")
	}
	if f.Sync() != nil {
		return errors.New("delivery journal unavailable")
	}
	return nil
}
