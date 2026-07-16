package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	DiagnosticSchemaVersion              = "datapan.diagnostic-envelope.v1"
	DiagnosticPinVersion                 = "datapan.health-diagnostic-contract-pin.v1"
	AcceptedDiagnosticRegistryRevision   = "8c5d397f13929ec2b85e63e4ca600887f37929b8"
	AcceptedDiagnosticSchemaSHA256       = "da254b40947462347fcda90fdd7686b6632c76943b438f2046a28f079f33e403"
	AcceptedDiagnosticMappingSHA256      = "da55d52d2ee1f197969ac63a1d5ab5b98e3b88fd65f90d6a48800d2e3c522d33"
	AcceptedDiagnosticConsumerSHA256     = "e831df46e50107c116132f423525af5b1ea8c9743c014956a2fc3732077db70c"
	AcceptedDiagnosticTestManifestSHA256 = "274d394133eb90fe5553bb47947644d45f338ad2e193345e13759f7bb9e2619b"
	AcceptedHealthProbeCatalogSHA256     = "e84f0da2f532a32833def1118a4610bf2322f370783d120b84cf85306d244840"
	maxDiagnosticEnvelopeBytes           = 256 * 1024
	mappingSchemaVersion                 = "datapan.data-go-kr-diagnostic-evidence-mapping.v1"
	consumerCompatibilitySchemaVersion   = "datapan.diagnostic-consumer-compatibility.v1"
)

var secretHashPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// DiagnosticContract is the offline compatibility boundary for the exact
// Registry revision accepted by issue #19. It does not publish, correlate, or
// project a diagnosis into Gatus.
type DiagnosticContract struct {
	RegistryRevision string
	SourceID         string
	ProviderID       string
	Schema           ArtifactPin
	Mapping          ArtifactPin
	Consumer         ArtifactPin
	TestManifest     ArtifactPin
	FixtureDirectory string
	schema           *jsonschema.Schema
	fixtureNames     []string
	testManifest     DiagnosticTestManifest
}

type diagnosticContractPin struct {
	SchemaVersion    string `json:"schema_version"`
	RegistryRevision string `json:"registry_revision"`
	SubjectIdentity  struct {
		SourceID   string `json:"source_id"`
		ProviderID string `json:"provider_id"`
	} `json:"subject_identity"`
	SchemaContract   ArtifactPin `json:"schema_contract"`
	MappingContract  ArtifactPin `json:"mapping_contract"`
	ConsumerContract ArtifactPin `json:"consumer_contract"`
	TestManifest     ArtifactPin `json:"test_manifest"`
	FixtureDirectory string      `json:"fixture_directory"`
}

type ArtifactPin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type diagnosticMappingContract struct {
	SchemaVersion  string `json:"schema_version"`
	Status         string `json:"status"`
	Provider       string `json:"provider"`
	EnvelopeSchema string `json:"envelope_schema"`
}

type diagnosticConsumerContract struct {
	SchemaVersion    string      `json:"schema_version"`
	Status           string      `json:"status"`
	Consumer         string      `json:"consumer"`
	SchemaContract   ArtifactPin `json:"schema_contract"`
	MappingContract  ArtifactPin `json:"mapping_contract"`
	FixtureContracts []string    `json:"fixture_contracts"`
}

type DiagnosticEnvelope struct {
	SchemaVersion  string              `json:"schema_version"`
	AssessedAt     time.Time           `json:"assessed_at"`
	Fixture        json.RawMessage     `json:"fixture,omitempty"`
	Subject        DiagnosticSubject   `json:"subject"`
	Cause          DiagnosticCause     `json:"cause"`
	Ownership      json.RawMessage     `json:"ownership"`
	Actions        json.RawMessage     `json:"actions"`
	EvidenceRefs   []json.RawMessage   `json:"evidence_refs"`
	Redaction      DiagnosticRedaction `json:"redaction"`
	OriginalSHA256 string              `json:"-"`
}

type DiagnosticSubject struct {
	SourceID    string `json:"source_id"`
	ProviderID  string `json:"provider_id"`
	DatasetID   string `json:"dataset_id"`
	OperationID string `json:"operation_id"`
}

type DiagnosticCause struct {
	Code          string `json:"code"`
	Determination string `json:"determination"`
	Layer         string `json:"layer"`
	ExplanationID string `json:"explanation_id"`
}

type DiagnosticRedaction struct {
	SecretValuesPresent          bool `json:"secret_values_present"`
	SecretHashesPresent          bool `json:"secret_hashes_present"`
	AuthorizationHeadersPresent  bool `json:"authorization_headers_present"`
	CredentialBearingURLsPresent bool `json:"credential_bearing_urls_present"`
	RawProviderTextPresent       bool `json:"raw_provider_text_present"`
	RawProviderURLsPresent       bool `json:"raw_provider_urls_present"`
	ResponseBodiesPresent        bool `json:"response_bodies_present"`
	UserIdentityPresent          bool `json:"user_identity_present"`
}

type DiagnosticBinding struct {
	OperationID      string `json:"operation_id"`
	ServiceID        string `json:"service_id"`
	RegistryRevision string `json:"registry_revision"`
	EnvelopeSHA256   string `json:"envelope_sha256"`
}

func LoadDiagnosticContract(path string) (DiagnosticContract, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return DiagnosticContract{}, err
	}
	var pin diagnosticContractPin
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pin); err != nil {
		return DiagnosticContract{}, errors.New("invalid diagnostic contract pin")
	}
	if err := ensureEOF(decoder); err != nil {
		return DiagnosticContract{}, errors.New("invalid diagnostic contract pin")
	}
	if pin.SchemaVersion != DiagnosticPinVersion || pin.RegistryRevision != AcceptedDiagnosticRegistryRevision || pin.SubjectIdentity.SourceID != "data_go_kr" || pin.SubjectIdentity.ProviderID != "data_go_kr" {
		return DiagnosticContract{}, errors.New("unsupported diagnostic contract pin")
	}
	wants := []struct {
		pin  ArtifactPin
		want string
	}{
		{pin.SchemaContract, AcceptedDiagnosticSchemaSHA256},
		{pin.MappingContract, AcceptedDiagnosticMappingSHA256},
		{pin.ConsumerContract, AcceptedDiagnosticConsumerSHA256},
		{pin.TestManifest, AcceptedDiagnosticTestManifestSHA256},
	}
	base := filepath.Dir(path)
	artifacts := make([][]byte, 0, len(wants))
	for _, item := range wants {
		if item.pin.SHA256 != item.want || !safeRelativePath(item.pin.Path) {
			return DiagnosticContract{}, errors.New("unsupported diagnostic artifact pin")
		}
		artifact, err := os.ReadFile(filepath.Join(base, item.pin.Path))
		if err != nil || digest(artifact) != item.want {
			return DiagnosticContract{}, errors.New("diagnostic artifact digest does not match pin")
		}
		artifacts = append(artifacts, artifact)
	}
	if !safeRelativePath(pin.FixtureDirectory) {
		return DiagnosticContract{}, errors.New("invalid diagnostic fixture directory")
	}

	var mapping diagnosticMappingContract
	if err := json.Unmarshal(artifacts[1], &mapping); err != nil || mapping.SchemaVersion != mappingSchemaVersion || mapping.Status != "draft" || mapping.Provider != "data.go.kr" || mapping.EnvelopeSchema != "drafts/diagnostic-envelope/datapan.diagnostic-envelope.v1.schema.json" {
		return DiagnosticContract{}, errors.New("unsupported diagnostic mapping contract")
	}
	var consumer diagnosticConsumerContract
	if err := json.Unmarshal(artifacts[2], &consumer); err != nil || consumer.SchemaVersion != consumerCompatibilitySchemaVersion || consumer.Status != "draft" || consumer.Consumer != "datapan-health" || consumer.SchemaContract.SHA256 != AcceptedDiagnosticSchemaSHA256 || consumer.MappingContract.SHA256 != AcceptedDiagnosticMappingSHA256 || len(consumer.FixtureContracts) != 11 {
		return DiagnosticContract{}, errors.New("unsupported diagnostic consumer contract")
	}
	testManifest, err := decodeDiagnosticTestManifest(artifacts[3])
	if err != nil {
		return DiagnosticContract{}, err
	}
	fixtureNames := append([]string(nil), consumer.FixtureContracts...)
	sort.Strings(fixtureNames)
	for index, name := range fixtureNames {
		if filepath.Base(name) != name || filepath.Ext(name) != ".json" || (index > 0 && fixtureNames[index-1] == name) {
			return DiagnosticContract{}, errors.New("invalid diagnostic fixture contract")
		}
	}

	var schemaDocument any
	if err := json.Unmarshal(artifacts[0], &schemaDocument); err != nil {
		return DiagnosticContract{}, errors.New("invalid diagnostic schema")
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("https://schemas.datapan.dev/datapan.diagnostic-envelope.v1.schema.json", schemaDocument); err != nil {
		return DiagnosticContract{}, errors.New("invalid diagnostic schema")
	}
	compiled, err := compiler.Compile("https://schemas.datapan.dev/datapan.diagnostic-envelope.v1.schema.json")
	if err != nil {
		return DiagnosticContract{}, errors.New("invalid diagnostic schema")
	}

	return DiagnosticContract{
		RegistryRevision: pin.RegistryRevision,
		SourceID:         pin.SubjectIdentity.SourceID,
		ProviderID:       pin.SubjectIdentity.ProviderID,
		Schema:           pin.SchemaContract,
		Mapping:          pin.MappingContract,
		Consumer:         pin.ConsumerContract,
		TestManifest:     pin.TestManifest,
		FixtureDirectory: filepath.Join(base, pin.FixtureDirectory),
		schema:           compiled,
		fixtureNames:     fixtureNames,
		testManifest:     testManifest,
	}, nil
}

func (c DiagnosticContract) Decode(r io.Reader) (DiagnosticEnvelope, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxDiagnosticEnvelopeBytes+1))
	if err != nil {
		return DiagnosticEnvelope{}, errors.New("diagnostic envelope could not be read")
	}
	if len(data) > maxDiagnosticEnvelopeBytes {
		return DiagnosticEnvelope{}, errors.New("diagnostic envelope exceeds 256 KiB")
	}
	if err := rejectSensitiveDiagnosticJSON(data); err != nil {
		return DiagnosticEnvelope{}, err
	}
	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return DiagnosticEnvelope{}, errors.New("diagnostic envelope is not valid JSON")
	}
	if c.schema == nil || c.schema.Validate(instance) != nil {
		return DiagnosticEnvelope{}, errors.New("diagnostic envelope does not match the pinned schema")
	}
	var envelope DiagnosticEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return DiagnosticEnvelope{}, errors.New("diagnostic envelope cannot be decoded")
	}
	if err := ensureEOF(decoder); err != nil {
		return DiagnosticEnvelope{}, errors.New("diagnostic envelope must contain exactly one JSON object")
	}
	if envelope.SchemaVersion != DiagnosticSchemaVersion || envelope.AssessedAt.IsZero() {
		return DiagnosticEnvelope{}, errors.New("unsupported diagnostic envelope")
	}
	envelope.OriginalSHA256 = digest(data)
	return envelope, nil
}

func (c DiagnosticContract) Resolve(envelope DiagnosticEnvelope, canaries CanaryConfig) (DiagnosticBinding, error) {
	if c.RegistryRevision != AcceptedDiagnosticRegistryRevision || canaries.CatalogSHA256 != AcceptedHealthProbeCatalogSHA256 || envelope.Subject.SourceID != c.SourceID || envelope.Subject.ProviderID != c.ProviderID {
		return DiagnosticBinding{}, errors.New("diagnostic subject is not bound to the accepted Registry revision")
	}
	var matched *Canary
	for index := range canaries.Canaries {
		if canaries.Canaries[index].OperationID == envelope.Subject.OperationID {
			if matched != nil {
				return DiagnosticBinding{}, errors.New("diagnostic subject maps to duplicate canaries")
			}
			matched = &canaries.Canaries[index]
		}
	}
	if matched == nil {
		return DiagnosticBinding{}, errors.New("diagnostic subject is not a configured canary")
	}
	entry, ok := canaries.Entry(*matched)
	if !ok || entry.Aliases.DatasetID != envelope.Subject.DatasetID || entry.Provider != "data.go.kr" {
		return DiagnosticBinding{}, errors.New("diagnostic subject does not match the configured operation identity")
	}
	return DiagnosticBinding{
		OperationID:      matched.OperationID,
		ServiceID:        matched.GatusEndpointKey,
		RegistryRevision: c.RegistryRevision,
		EnvelopeSHA256:   envelope.OriginalSHA256,
	}, nil
}

func (c DiagnosticContract) FixtureNames() []string {
	return append([]string(nil), c.fixtureNames...)
}

func (c DiagnosticContract) ReadFixture(name string) ([]byte, error) {
	if index := sort.SearchStrings(c.fixtureNames, name); index >= len(c.fixtureNames) || c.fixtureNames[index] != name {
		return nil, errors.New("fixture is not part of the accepted consumer contract")
	}
	data, err := os.ReadFile(filepath.Join(c.FixtureDirectory, name))
	if err != nil {
		return nil, errors.New("accepted diagnostic fixture is missing")
	}
	return data, nil
}

func safeRelativePath(path string) bool {
	clean := filepath.Clean(path)
	return path != "" && !filepath.IsAbs(path) && clean == path && clean != "." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func rejectSensitiveDiagnosticJSON(data []byte) error {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return errors.New("diagnostic envelope is not valid JSON")
	}
	if containsSensitiveDiagnosticValue(value) {
		return errors.New("diagnostic envelope contains prohibited sensitive evidence")
	}
	return nil
}

func containsSensitiveDiagnosticValue(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToLower(key))
			switch normalized {
			case "secret", "secret_value", "secret_values", "secret_hash", "secret_hashes", "authorization", "authorization_header", "authorization_headers", "credential_url", "credential_bearing_url", "credential_bearing_urls", "query_url", "request_url", "raw_url", "provider_url", "raw_provider_url", "raw_provider_urls", "provider_message", "provider_text", "raw_provider_text", "response_body", "response_bodies", "response_rows", "user_id", "user_identity", "credential_id", "credential_hash", "credential_fingerprint":
				return true
			}
			if containsSensitiveDiagnosticValue(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSensitiveDiagnosticValue(child) {
				return true
			}
		}
	case string:
		trimmed := strings.TrimSpace(typed)
		lower := strings.ToLower(trimmed)
		return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "bearer ") || strings.HasPrefix(lower, "basic ") || secretHashPattern.MatchString(trimmed)
	}
	return false
}
