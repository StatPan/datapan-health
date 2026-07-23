package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"
)

const OperationManifestReceiptVersion = "datapan.health-operation-manifest-receipt.v1"

var operationIdentityFields = []string{
	"provider",
	"dataset_id",
	"protocol",
	"source_system",
	"upstream_operation_key",
	"endpoint",
	"method_or_action",
	"operation_name",
}

// OperationManifestReceipt is the redacted, Health-owned receipt for a pinned
// Registry operation manifest. It is an input to verification, not an
// execution policy or a scheduling instruction.
type OperationManifestReceipt struct {
	SchemaVersion string `json:"schema_version"`
	Registry      struct {
		Revision string `json:"revision"`
	} `json:"registry"`
	Acquisition struct {
		AcquiredAt time.Time `json:"acquired_at"`
		Method     string    `json:"method"`
	} `json:"acquisition"`
	Manifest struct {
		SchemaVersion string `json:"schema_version"`
		Path          string `json:"path"`
		Bytes         int64  `json:"bytes"`
		SHA256        string `json:"sha256"`
	} `json:"manifest"`
	ReleaseManifest struct {
		Path   string `json:"path"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"release_manifest"`
	Schema struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"schema"`
	SourceSnapshot struct {
		Path   string `json:"path"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"source_snapshot"`
	Denominator struct {
		OperationStatusSubjects int            `json:"operation_status_subjects"`
		Protocols               map[string]int `json:"protocols"`
		APIMetadataCount        int            `json:"api_metadata_count"`
		Exclusions              map[string]int `json:"exclusions"`
	} `json:"denominator"`
	ServiceCanaries struct {
		Count                          int    `json:"count"`
		Role                           string `json:"role"`
		IncludedInOperationDenominator bool   `json:"included_in_operation_denominator"`
	} `json:"service_canaries"`
}

// OperationManifest is the immutable Registry artifact reduced only to the
// fields needed to validate and preserve an operation-status subject.
type OperationManifest struct {
	SchemaVersion    string                   `json:"schema_version"`
	Authority        string                   `json:"authority"`
	SourceSnapshot   ManifestSourceSnapshot   `json:"source_snapshot"`
	IdentityContract ManifestIdentityContract `json:"identity_contract"`
	Summary          ManifestSummary          `json:"summary"`
	Operations       []ManifestOperation      `json:"operations"`
}

type ManifestSourceSnapshot struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type ManifestIdentityContract struct {
	Algorithm string   `json:"algorithm"`
	Fields    []string `json:"fields"`
}

type ManifestSummary struct {
	APIOperations      int            `json:"api_operations"`
	Protocols          map[string]int `json:"protocols"`
	Eligibility        map[string]int `json:"eligibility"`
	Exclusions         map[string]int `json:"exclusions"`
	IdentityCollisions int            `json:"identity_collisions"`
	IdentityOmissions  int            `json:"identity_omissions"`
}

type ManifestOperation struct {
	OperationID string `json:"operation_id"`
	Protocol    string `json:"protocol"`
	Provenance  struct {
		Provider             string `json:"provider"`
		DatasetID            string `json:"dataset_id"`
		OperationName        string `json:"operation_name"`
		SourceSystem         string `json:"source_system"`
		UpstreamOperationKey string `json:"upstream_operation_key"`
		SourceURL            string `json:"source_url"`
	} `json:"provenance"`
	Transport struct {
		Endpoint       *string `json:"endpoint"`
		Method         *string `json:"method"`
		Action         *string `json:"action"`
		MethodEvidence string  `json:"method_evidence"`
	} `json:"transport"`
	CallReadiness json.RawMessage `json:"call_readiness"`
	Requirements  json.RawMessage `json:"requirements"`
	Eligibility   struct {
		Status         string  `json:"status"`
		ExcludedReason *string `json:"excluded_reason"`
	} `json:"eligibility"`
}

type RegistryReleaseManifest struct {
	SchemaVersion string `json:"schema_version"`
	Artifacts     []struct {
		Path   string `json:"path"`
		Kind   string `json:"kind"`
		Schema string `json:"schema"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"artifacts"`
}

type OperationManifestVerification struct {
	SchemaVersion string `json:"schema_version"`
	Registry      struct {
		Revision string `json:"revision"`
	} `json:"registry"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Integrity      string `json:"integrity"`
	Denominator    struct {
		OperationStatusSubjects int            `json:"operation_status_subjects"`
		Protocols               map[string]int `json:"protocols"`
		APIMetadataCount        int            `json:"api_metadata_count"`
	} `json:"denominator"`
	ServiceCanaries struct {
		Count                          int  `json:"count"`
		IncludedInOperationDenominator bool `json:"included_in_operation_denominator"`
	} `json:"service_canaries"`
}

func LoadOperationManifestReceipt(path string) (OperationManifestReceipt, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return OperationManifestReceipt{}, err
	}
	var receipt OperationManifestReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil || ensureEOF(decoder) != nil || !validOperationManifestReceipt(receipt) {
		return OperationManifestReceipt{}, errors.New("invalid operation manifest receipt")
	}
	return receipt, nil
}

func LoadPinnedOperationManifest(manifestPath, releaseManifestPath, receiptPath string) (OperationManifest, OperationManifestReceipt, error) {
	receipt, err := LoadOperationManifestReceipt(receiptPath)
	if err != nil {
		return OperationManifest{}, OperationManifestReceipt{}, err
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return OperationManifest{}, OperationManifestReceipt{}, err
	}
	if int64(len(raw)) != receipt.Manifest.Bytes || digest(raw) != receipt.Manifest.SHA256 {
		return OperationManifest{}, OperationManifestReceipt{}, errors.New("operation manifest does not match immutable receipt")
	}
	if err := validateReleaseManifest(releaseManifestPath, receipt); err != nil {
		return OperationManifest{}, OperationManifestReceipt{}, err
	}
	var manifest OperationManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || ensureEOF(decoder) != nil {
		return OperationManifest{}, OperationManifestReceipt{}, errors.New("invalid operation manifest")
	}
	if err := manifest.Validate(receipt); err != nil {
		return OperationManifest{}, OperationManifestReceipt{}, err
	}
	return manifest, receipt, nil
}

func validateReleaseManifest(path string, receipt OperationManifestReceipt) error {
	raw, err := os.ReadFile(path)
	if err != nil || int64(len(raw)) != receipt.ReleaseManifest.Bytes || digest(raw) != receipt.ReleaseManifest.SHA256 {
		return errors.New("release manifest does not match immutable receipt")
	}
	var release RegistryReleaseManifest
	if err := json.Unmarshal(raw, &release); err != nil || release.SchemaVersion != "datapan.release-manifest.v1" {
		return errors.New("release manifest contract is unsupported")
	}
	for _, artifact := range release.Artifacts {
		if artifact.Path == receipt.Manifest.Path && artifact.Kind == "data_go_kr_operation_manifest" && artifact.Schema == "https://schemas.datapan.dev/datapan.data-go-kr-operation-manifest.v1.schema.json" && artifact.Bytes == receipt.Manifest.Bytes && artifact.SHA256 == receipt.Manifest.SHA256 {
			return nil
		}
	}
	return errors.New("release manifest does not bind operation manifest")
}

func (m OperationManifest) Validate(receipt OperationManifestReceipt) error {
	if m.SchemaVersion != receipt.Manifest.SchemaVersion || m.Authority != "datapan-registry" || m.SourceSnapshot != (ManifestSourceSnapshot{Path: receipt.SourceSnapshot.Path, Bytes: receipt.SourceSnapshot.Bytes, SHA256: receipt.SourceSnapshot.SHA256}) || m.IdentityContract.Algorithm != "sha256-length-prefixed-utf8-v1" || !sameStrings(m.IdentityContract.Fields, operationIdentityFields) {
		return errors.New("operation manifest contract is unsupported")
	}
	if m.Summary.APIOperations != receipt.Denominator.OperationStatusSubjects || !sameCounts(m.Summary.Protocols, receipt.Denominator.Protocols) || !sameCounts(m.Summary.Exclusions, sourceExclusions(receipt.Denominator.Exclusions)) || m.Summary.IdentityCollisions != 0 || m.Summary.IdentityOmissions != 0 || len(m.Operations) != receipt.Denominator.OperationStatusSubjects {
		return errors.New("operation manifest denominator does not match receipt")
	}
	seen := make(map[string]bool, len(m.Operations))
	protocols := map[string]int{}
	eligibility := map[string]int{}
	datasets := map[string]bool{}
	for _, operation := range m.Operations {
		if err := operation.validateIdentity(); err != nil || seen[operation.OperationID] {
			return errors.New("operation manifest contains an invalid or duplicate operation subject")
		}
		seen[operation.OperationID] = true
		protocols[operation.Protocol]++
		eligibility[operation.Eligibility.Status]++
		datasets[operation.Provenance.DatasetID] = true
	}
	if !sameCounts(protocols, receipt.Denominator.Protocols) || !sameCounts(eligibility, map[string]int{"approval_required": receipt.Denominator.Exclusions["required_parameter_approval"], "excluded": receipt.Denominator.Exclusions["endpoint_missing"]}) || len(datasets) != receipt.Denominator.APIMetadataCount {
		return errors.New("operation manifest derived counts do not match receipt")
	}
	return nil
}

// StatusSubject returns the only permitted subject identity for Health's
// operation denominator. API, dataset, host, and endpoint are metadata and
// must never be used as deduplication keys.
func (operation ManifestOperation) StatusSubject() string { return operation.OperationID }

func (operation ManifestOperation) validateIdentity() error {
	if !sha256Pattern.MatchString(operation.OperationID) || operation.Provenance.Provider != "data.go.kr" || operation.Provenance.DatasetID == "" || operation.Provenance.OperationName == "" || operation.Provenance.SourceSystem == "" || operation.Provenance.UpstreamOperationKey == "" || operation.Provenance.SourceURL == "" {
		return errors.New("operation identity fields are incomplete")
	}
	if _, err := url.ParseRequestURI(operation.Provenance.SourceURL); err != nil {
		return errors.New("operation provenance URL is invalid")
	}
	methodOrAction := ""
	switch operation.Protocol {
	case "REST":
		if operation.Transport.Method == nil || *operation.Transport.Method != "GET" || operation.Transport.Action != nil || operation.Transport.MethodEvidence != "registry_default_get" {
			return errors.New("REST operation identity is invalid")
		}
		methodOrAction = *operation.Transport.Method
	case "SOAP":
		if operation.Transport.Method != nil || operation.Transport.Action == nil || *operation.Transport.Action == "" || operation.Transport.MethodEvidence != "soap_action" {
			return errors.New("SOAP operation identity is invalid")
		}
		methodOrAction = *operation.Transport.Action
	default:
		return errors.New("operation protocol is invalid")
	}
	if operation.Eligibility.Status != "approval_required" && operation.Eligibility.Status != "excluded" {
		return errors.New("operation eligibility is invalid")
	}
	endpoint := ""
	if operation.Transport.Endpoint != nil {
		endpoint = *operation.Transport.Endpoint
	}
	fields := []string{operation.Provenance.Provider, operation.Provenance.DatasetID, operation.Protocol, operation.Provenance.SourceSystem, operation.Provenance.UpstreamOperationKey, endpoint, methodOrAction, operation.Provenance.OperationName}
	if lengthPrefixedSHA256(fields) != operation.OperationID {
		return errors.New("operation identity hash does not match contract")
	}
	return nil
}

func BuildOperationManifestVerification(manifest OperationManifest, receipt OperationManifestReceipt) OperationManifestVerification {
	var verification OperationManifestVerification
	verification.SchemaVersion = "datapan.health-operation-manifest-verification.v1"
	verification.Registry.Revision = receipt.Registry.Revision
	verification.ManifestSHA256 = receipt.Manifest.SHA256
	verification.Integrity = "verified"
	verification.Denominator.OperationStatusSubjects = len(manifest.Operations)
	verification.Denominator.Protocols = copyCounts(manifest.Summary.Protocols)
	verification.Denominator.APIMetadataCount = receipt.Denominator.APIMetadataCount
	verification.ServiceCanaries.Count = receipt.ServiceCanaries.Count
	verification.ServiceCanaries.IncludedInOperationDenominator = receipt.ServiceCanaries.IncludedInOperationDenominator
	return verification
}

func validOperationManifestReceipt(receipt OperationManifestReceipt) bool {
	return receipt.SchemaVersion == OperationManifestReceiptVersion && commitPattern.MatchString(receipt.Registry.Revision) && !receipt.Acquisition.AcquiredAt.IsZero() && receipt.Acquisition.Method == "git_commit" && receipt.Manifest.SchemaVersion == "datapan.data-go-kr-operation-manifest.v1" && receipt.Manifest.Path == "reports/data-go-kr/operation-manifest.json" && receipt.Manifest.Bytes > 0 && sha256Pattern.MatchString(receipt.Manifest.SHA256) && receipt.ReleaseManifest.Path == "manifest.json" && receipt.ReleaseManifest.Bytes > 0 && sha256Pattern.MatchString(receipt.ReleaseManifest.SHA256) && receipt.Schema.Path == "schemas/datapan.data-go-kr-operation-manifest.v1.schema.json" && sha256Pattern.MatchString(receipt.Schema.SHA256) && receipt.SourceSnapshot.Path == "data/data-go-kr.registry.json" && receipt.SourceSnapshot.Bytes > 0 && sha256Pattern.MatchString(receipt.SourceSnapshot.SHA256) && receipt.Denominator.OperationStatusSubjects > 0 && receipt.Denominator.APIMetadataCount > 0 && sameCounts(receipt.Denominator.Protocols, map[string]int{"REST": 12350, "SOAP": 35}) && len(receipt.Denominator.Exclusions) == 5 && receipt.Denominator.Exclusions["link_operations"] >= 0 && receipt.Denominator.Exclusions["operationless_catalog_entries"] >= 0 && receipt.Denominator.Exclusions["filedata_catalog_entries"] >= 0 && receipt.Denominator.Exclusions["endpoint_missing"] >= 0 && receipt.Denominator.Exclusions["required_parameter_approval"] >= 0 && receipt.ServiceCanaries.Count > 0 && receipt.ServiceCanaries.Role == "separate_observation_input" && !receipt.ServiceCanaries.IncludedInOperationDenominator
}

func sourceExclusions(exclusions map[string]int) map[string]int {
	return map[string]int{"link_operations": exclusions["link_operations"], "operationless_catalog_entries": exclusions["operationless_catalog_entries"], "filedata_catalog_entries": exclusions["filedata_catalog_entries"]}
}

func lengthPrefixedSHA256(fields []string) string {
	hash := sha256.New()
	for _, field := range fields {
		_, _ = fmt.Fprintf(hash, "%d:%s", len([]byte(field)), field)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func sameCounts(got, want map[string]int) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

func copyCounts(counts map[string]int) map[string]int {
	copy := make(map[string]int, len(counts))
	for key, value := range counts {
		copy[key] = value
	}
	return copy
}
