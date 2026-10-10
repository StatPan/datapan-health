package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const pinnedOperationPlanTestGatusImage = "ghcr.io/twin/gatus:v5.36.0@sha256:c5f210d095fa78e6efaa20ffeb14803f2ba4f10615e16a6d12087697149617f0"
const partialRegistryIdentityFixtureSHA256 = "d7f7da4da9e959cb99561f058504c02a17fe276c6bb68e53faef1647f3bddcda"

type operationPlanPopulationIdentity struct {
	SourceID         string
	Provider         string
	AdapterID        string
	InventoryStatus  string
	InventoryUnknown bool
	OperationID      string
	Protocol         string
	DatasetID        string
}

type partialRegistryIdentityFixture struct {
	SchemaVersion               string `json:"schema_version"`
	DerivedFromRegistryRevision string `json:"derived_from_registry_revision"`
	DerivedFromIndexSHA256      string `json:"derived_from_index_sha256"`
	SourceScopes                []struct {
		SourceID         string `json:"source_id"`
		Provider         string `json:"provider"`
		AdapterID        string `json:"adapter_id"`
		InventoryStatus  string `json:"inventory_status"`
		InventoryUnknown bool   `json:"inventory_unknown"`
		OperationID      string `json:"operation_id"`
		Protocol         string `json:"protocol"`
	} `json:"source_scopes"`
}

func TestOperationPlanManifestDerivedSyntheticPopulation(t *testing.T) {
	if os.Getenv("HEALTH_OPERATION_FULL_POPULATION_TEST") != "1" {
		t.Skip("run with make operation-plan-full-population for bounded manifest-sized source QA")
	}

	metadata, canaries, plan, planRoot, identities := loadManifestDerivedPopulationPlan(t)
	const concurrency = 32
	activationEntries := make([]OperationGatusActivationEntry, len(identities))
	for index, identity := range identities {
		activationEntries[index] = OperationGatusActivationEntry{SourceID: identity.SourceID, OperationID: identity.OperationID}
	}
	activationRaw, err := json.Marshal(OperationGatusActivation{
		SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(),
		IndexSHA256: plan.IndexSHA256(), Operations: activationEntries,
	})
	if err != nil {
		t.Fatal(err)
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationRaw, plan)
	if err != nil {
		t.Fatalf("manifest-derived test population could not bind exact IDs: %v", err)
	}
	canaryRaw, err := os.ReadFile("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	baseConfig := []byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: placeholder\n")
	artifacts, err := GenerateOperationGatusArtifacts(baseConfig, digestOperationGatusBytes(canaryRaw), canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatalf("manifest-sized exact Gatus mapping could not be generated: %v", err)
	}
	var mapping OperationGatusIdentityMapping
	if json.Unmarshal(artifacts.Mapping, &mapping) != nil || mapping.KnownPlanOperations != len(identities) || mapping.ActivatedPlanOperations != len(identities) || mapping.ConfiguredExternalEndpoints != len(identities) {
		t.Fatalf("generated operation-to-Gatus mapping did not preserve the full known registered population: known=%d activated=%d endpoints=%d expected=%d", mapping.KnownPlanOperations, mapping.ActivatedPlanOperations, mapping.ConfiguredExternalEndpoints, len(identities))
	}

	root := t.TempDir()
	paths := operationPlanTestRuntimePaths(root)
	paths.ActivationPath = filepath.Join(root, "activation.json")
	paths.ActivationSHA256 = activationSHA
	planPinRaw, err := json.Marshal(operationObservationPlanRuntimePin{SchemaVersion: OperationObservationPlanRuntimePinSchema, Plan: plan.binding})
	if err != nil {
		t.Fatal(err)
	}
	canaryConfigRaw, err := os.ReadFile("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	metadataRaw, err := os.ReadFile("../../config/registry/api-metadata.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	metadataPinRaw, err := os.ReadFile("../../config/registry/api-metadata-source-pin.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string][]byte{
		paths.PlanPinPath: planPinRaw, paths.CanaryConfigPath: canaryConfigRaw,
		paths.RegistryMetadataPath: metadataRaw, paths.RegistryMetadataPin: metadataPinRaw,
		paths.BaseGatusConfigPath: baseConfig, paths.GeneratedConfigPath: artifacts.Config,
		paths.IdentityMappingPath: artifacts.Mapping, paths.RuntimePinPath: artifacts.RuntimePin,
		paths.ActivationPath: activationRaw,
	} {
		if err := os.WriteFile(path, raw, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	verifiedRuntime, err := verifyOperationGatusRuntimeArtifacts(paths, canaryConfigRaw, canaries, metadata, plan)
	if err != nil || len(verifiedRuntime.ActiveTargets) != len(identities) {
		t.Fatalf("generated full population did not verify as an executable plan: admitted=%d err=%v", len(verifiedRuntime.ActiveTargets), err)
	}
	lock := testOperationPlanRuntimeLock(strings.Repeat("9", 64))
	resolver, err := NewPinnedOperationPlanProbeExpectationResolver(plan, lock, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewOperationPlanProbeHistoryValidator(strings.Repeat("8", 40), resolver)
	if err != nil {
		t.Fatal(err)
	}
	attemptRoot := filepath.Join(root, "attempts")
	quotaRoot := filepath.Join(root, "quotas")
	historyRoot := filepath.Join(root, "history")
	attempts, err := OpenOperationAttemptStore(attemptRoot)
	if err != nil {
		t.Fatal(err)
	}
	quotas, err := OpenOperationQuotaAuthority(quotaRoot)
	if err != nil {
		t.Fatal(err)
	}
	history, err := OpenOperationHistoryStore(historyRoot, maxOperationHistoryStoreBytes, validator)
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(planRoot, filepath.FromSlash(plan.binding.IndexPath))
	probeConfig, err := OperationPlanProbeConfigFromRuntimeLock(lock, "amd64", "/synthetic/datapan", indexPath, filepath.Join(root, "credential-bindings.json"), filepath.Join(root, "private-receipts"), nil)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := newOperationPlanWorker(OperationPlanWorkerConfig{
		Runtime: verifiedRuntime, Runner: schedulerSyntheticReceiptExecutor{}, Attempts: attempts, Quotas: quotas,
		History: history, HistoryValidator: validator, Gatus: &schedulerSyntheticGatus{},
		RuntimeLock: lock, Architecture: "amd64", AttemptLease: time.Minute, QuotaLease: time.Minute,
	}, probeConfig)
	if err != nil {
		t.Fatalf("bounded synthetic worker could not bind every known Registry operation: %v", err)
	}
	client := &schedulerSyntheticGatus{}
	worker.gatus = client
	scheduler, err := NewOperationPlanScheduler(OperationPlanSchedulerConfig{
		Worker: worker, MaxConcurrent: concurrency, MaxStartsPerPass: concurrency,
		MaxDeliveriesPerPass: concurrency, CandidateScanPerPass: operationPlanSchedulerMaximumScanBudget,
		DeliveryLease: time.Minute,
	})
	if err != nil {
		t.Fatalf("bounded production scheduler rejected the explicit synthetic population policy: %v", err)
	}
	// This explicit source-QA target is bounded by a measured 45-minute wall
	// clock budget. Its passAt value advances virtual scheduler time by one
	// second per iteration; it does not prove production loop cadence.
	controllerContext, cancelController := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancelController()
	controllerStart := time.Now().UTC()
	var controllerStatus OperationPlanSchedulerStatus
	completed := false
	for pass := 0; pass < 1200; pass++ {
		passAt := controllerStart.Add(time.Duration(pass) * time.Second)
		if err := scheduler.ProcessDue(controllerContext, passAt); err != nil {
			t.Fatalf("bounded controller pass %d failed: %v", pass, err)
		}
		scheduler.Wait()
		controllerStatus = scheduler.Status(passAt)
		if controllerStatus.RequestStartsSinceStart == uint64(len(identities)) && controllerStatus.ReadbacksSinceStart == uint64(len(identities)) {
			completed = true
			break
		}
	}
	if !completed || controllerStatus.ExecutionFailuresSinceStart != 0 || controllerStatus.DeliveryFailuresSinceStart != 0 {
		t.Fatalf("bounded production controller did not reconcile execution and delivery within the configured passes: started=%d readbacks=%d execution_failures=%d delivery_failures=%d expected=%d", controllerStatus.RequestStartsSinceStart, controllerStatus.ReadbacksSinceStart, controllerStatus.ExecutionFailuresSinceStart, controllerStatus.DeliveryFailuresSinceStart, len(identities))
	}

	usage, err := history.Usage(context.Background())
	if err != nil || usage.RecordCount != int64(len(identities)) || usage.ReservationCount != 0 {
		t.Fatalf("durable history did not reconcile to the manifest-derived population: records=%d reservations=%d expected=%d err=%v", usage.RecordCount, usage.ReservationCount, len(identities), err)
	}
	if pushes, readbacks := client.counts(); pushes != len(identities) || readbacks != len(identities) {
		t.Fatalf("independent delivery did not reconcile every admitted identity: pushes=%d readbacks=%d expected=%d", pushes, readbacks, len(identities))
	}
	client.mu.Lock()
	seenGatusKeys := make(map[string]struct{}, len(client.results))
	for key := range client.results {
		seenGatusKeys[key] = struct{}{}
	}
	client.mu.Unlock()
	if len(seenGatusKeys) != len(verifiedRuntime.ActiveTargets) {
		t.Fatalf("synthetic Gatus outbox covered %d of %d exact generated endpoint keys", len(seenGatusKeys), len(verifiedRuntime.ActiveTargets))
	}
	for _, target := range verifiedRuntime.ActiveTargets {
		if _, delivered := seenGatusKeys[target.GatusEndpointKey]; !delivered {
			t.Fatalf("synthetic receipt delivery omitted a verified Gatus identity key for operation %q", target.Record.OperationID)
		}
	}
	storeSnapshots, err := attempts.SnapshotReadModelAttempts()
	if err != nil || len(storeSnapshots) != len(identities) {
		t.Fatalf("durable attempt store did not retain every admitted identity: rows=%d expected=%d err=%v", len(storeSnapshots), len(identities), err)
	}
	readModel, err := NewOperationReadModel(plan, metadata, nil, time.Now().UTC())
	if err != nil {
		t.Fatal("public Registry read model rejected the verified population:", err)
	}
	now := time.Now().UTC().Add(time.Second)
	for offset := 0; ; {
		next, complete, refreshErr := readModel.RefreshFromStoreBatch(attempts, offset, operationAttemptIdentityBatchMaximum, now)
		if refreshErr != nil {
			t.Fatalf("bounded read-model refresh failed at offset %d: %v", offset, refreshErr)
		}
		if complete {
			break
		}
		offset = next
	}
	seen := make(map[string]struct{}, len(identities))
	expectedIdentities := populationIdentityMap(identities)
	cursor := ""
	for {
		page, pageErr := readModel.PageOperations(OperationPageQuery{Limit: operationReadModelMaximumPage, Cursor: cursor}, now)
		if pageErr != nil {
			t.Fatal("bounded public page retrieval failed:", pageErr)
		}
		if page.IdentityCounts.Known != len(identities) || page.IdentityCounts.Attempted != len(identities) || page.IdentityCounts.Persisted != len(identities) || page.IdentityCounts.ReadbackVerified != len(identities) || page.IdentityCounts.InventoryUnknownScopes != plan.Counts().InventoryUnknownScopes || page.IdentityCounts.InventoryUnknownOperations != unknownOperationCount(identities) || page.IdentityCounts.Missing != 0 || page.IdentityCounts.Late != 0 {
			t.Fatalf("public identity sets did not reconcile while preserving partial-provider unknowns: known=%d attempted=%d persisted=%d delivered=%d unknown_scopes=%d unknown_operations=%d missing=%d late=%d expected=%d", page.IdentityCounts.Known, page.IdentityCounts.Attempted, page.IdentityCounts.Persisted, page.IdentityCounts.ReadbackVerified, page.IdentityCounts.InventoryUnknownScopes, page.IdentityCounts.InventoryUnknownOperations, page.IdentityCounts.Missing, page.IdentityCounts.Late, len(identities))
		}
		for _, operation := range page.Operations {
			key := operationReadModelIdentityKey(operation.SourceID, operation.RegistryOperationID)
			identity, exists := expectedIdentities[key]
			_, duplicate := seen[key]
			if !exists || operation.Provider != identity.Provider || operation.AdapterID != identity.AdapterID || operation.InventoryUnknown != identity.InventoryUnknown || duplicate || operation.AttemptState != "observed" || operation.ObservationState != "current_pass" || operation.GatusDeliveryState != "readback_verified" {
				t.Fatalf("public paging repeated or misclassified an admitted operation at total %d", len(seen))
			}
			seen[key] = struct{}{}
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != len(identities) {
		t.Fatalf("public paged retrieval covered %d of %d known manifest-derived identities", len(seen), len(identities))
	}
	t.Logf("synthetic source QA reconciled %d known Registry operations (%d pinned data.go.kr identities plus %d identities from explicitly partial provider scopes) across bounded dispatch, receipt history, durable attempts, delivery bookkeeping, and public paging; provider discovery remains unknown", len(identities), metadata.pin.OperationCount, len(identities)-metadata.pin.OperationCount)
}

func TestOperationPlanPinnedGatusSyntheticReceiptIntegration(t *testing.T) {
	if os.Getenv("HEALTH_OPERATION_GATUS_INTEGRATION_TEST") != "1" {
		t.Skip("run with make operation-plan-gatus-integration for pinned local Gatus source QA")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("Docker is required for the pinned Gatus integration target: %v", err)
	}
	worker, attempts, history, _, target := newOperationPlanSchedulerTestWorker(t)
	token := "synthetic-local-gatus-token"
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, worker.runtime.Artifacts.Config, 0o444); err != nil {
		t.Fatal(err)
	}
	containerName := fmt.Sprintf("health-operation-plan-test-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "--force", containerName).Run()
	}()
	start := exec.CommandContext(ctx, "docker", "run", "--detach", "--rm", "--name", containerName,
		"--publish", "127.0.0.1::8080", "--volume", configPath+":/config/config.yaml:ro",
		"--env", "GATUS_TOKEN="+token, pinnedOperationPlanTestGatusImage)
	if output, err := start.CombinedOutput(); err != nil {
		t.Fatalf("pinned Gatus container did not start (provider requests are not part of this test): %v; output=%s", err, strings.TrimSpace(string(output)))
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", containerName, "8080/tcp").Output()
	if err != nil {
		t.Fatal("could not inspect the isolated local Gatus listener:", err)
	}
	address := strings.TrimSpace(string(portOutput))
	if index := strings.LastIndex(address, ":"); index < 0 || index == len(address)-1 {
		t.Fatal("isolated Gatus listener did not publish a local port")
	}
	baseURL := "http://" + address
	readyClient := &http.Client{Timeout: time.Second}
	ready := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/health", nil)
		if requestErr == nil {
			response, requestErr := readyClient.Do(request)
			if requestErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					ready = true
					break
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		t.Fatal("pinned Gatus did not become ready with the generated one-operation configuration")
	}
	delivery, err := NewOperationPlanGatusDelivery(baseURL, token, 3*time.Second)
	if err != nil {
		t.Fatal("local Gatus delivery client rejected the isolated listener:", err)
	}
	worker.gatus = delivery
	scheduler, err := NewOperationPlanScheduler(OperationPlanSchedulerConfig{
		Worker: worker, MaxConcurrent: 1, MaxStartsPerPass: 1, MaxDeliveriesPerPass: 1,
		CandidateScanPerPass: 2, DeliveryLease: time.Minute,
	})
	if err != nil {
		t.Fatal("bounded production scheduler rejected the one-operation synthetic plan:", err)
	}
	schedulerStart := time.Now().UTC()
	for pass := 0; pass < 3; pass++ {
		if err := scheduler.ProcessDue(ctx, schedulerStart.Add(time.Duration(pass)*time.Second)); err != nil {
			t.Fatalf("bounded production scheduler pass failed: %v", err)
		}
		scheduler.Wait()
	}
	latest, found, err := attempts.Latest(target.Record.SourceID, target.Record.OperationID)
	if err != nil || !found || latest.State != "observed" || latest.DeliveryState != "readback_verified" || latest.GatusReceivedAt.IsZero() || latest.Result == nil || latest.Result.ObservedAt.IsZero() {
		t.Fatalf("real Gatus readback did not persist distinct provider and Gatus event times: found=%t delivery=%s err=%v", found, latest.DeliveryState, err)
	}
	usage, err := history.Usage(context.Background())
	if err != nil || usage.RecordCount != 1 || usage.ReservationCount != 0 {
		t.Fatalf("real Gatus delivery was not backed by one durable validated synthetic receipt: records=%d reservations=%d err=%v", usage.RecordCount, usage.ReservationCount, err)
	}
	if strings.Contains(string(worker.runtime.Artifacts.Config), token) || strings.Contains(string(worker.runtime.Artifacts.Mapping), token) {
		t.Fatal("synthetic Gatus token appeared in generated runtime artifacts")
	}
	t.Logf("pinned Gatus v5.36.0 accepted one generated operation registration and verified its synthetic receipt by exact-key readback")
}

func loadManifestDerivedPopulationPlan(t *testing.T) (VerifiedRegistryAPIMetadata, CanaryConfig, PinnedOperationObservationPlan, string, []operationPlanPopulationIdentity) {
	t.Helper()
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	metadataArtifact, err := LoadRegistryAPIMetadata("../../config/registry/api-metadata.v1.json", "../../config/registry/api-metadata-source-pin.v1.json", canaries)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := NewVerifiedRegistryAPIMetadata(metadataArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.operations) != metadata.pin.OperationCount || metadata.pin.OperationCount < 1 {
		t.Fatalf("pinned metadata operation population is inconsistent: operations=%d pin=%d", len(metadata.operations), metadata.pin.OperationCount)
	}
	identities := make([]operationPlanPopulationIdentity, 0, metadata.pin.OperationCount+4)
	for _, api := range metadataArtifact.APIs {
		for _, operation := range api.Operations {
			identities = append(identities, operationPlanPopulationIdentity{
				SourceID: "data_go_kr", Provider: "data.go.kr", AdapterID: "data-go-kr", InventoryStatus: "source_complete",
				OperationID: operation.RegistryOperationID, Protocol: operation.Protocol, DatasetID: operation.DatasetID,
			})
		}
	}
	fixture := loadPartialRegistryIdentityFixture(t)
	for _, scope := range fixture.SourceScopes {
		identities = append(identities, operationPlanPopulationIdentity{
			SourceID: scope.SourceID, Provider: scope.Provider, AdapterID: scope.AdapterID,
			InventoryStatus: scope.InventoryStatus, InventoryUnknown: scope.InventoryUnknown,
			OperationID: scope.OperationID, Protocol: scope.Protocol,
		})
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].SourceID != identities[j].SourceID {
			return identities[i].SourceID < identities[j].SourceID
		}
		return identities[i].OperationID < identities[j].OperationID
	})
	identityKeys := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		key := operationReadModelIdentityKey(identity.SourceID, identity.OperationID)
		if _, duplicate := identityKeys[key]; duplicate {
			t.Fatalf("manifest-derived population contains a duplicate Registry identity: %s", key)
		}
		identityKeys[key] = struct{}{}
	}
	root, binding := writeManifestDerivedSyntheticPlan(t, metadataArtifact, metadata, identities, fixture)
	plan, err := LoadPinnedOperationObservationPlan(root, binding)
	if err != nil {
		t.Fatalf("local operation-plan binding could not verify the full mixed-source identity set: %v", err)
	}
	counts := plan.Counts()
	if counts.KnownOperations != len(identities) || counts.RequestPlansComplete != len(identities) || counts.RuntimeBindingsBound != len(identities) || counts.Admitted != len(identities) || plan.ExecutableOperations() != len(identities) {
		t.Fatalf("local synthetic binding did not cover every registered identity: known=%d complete=%d bound=%d admitted=%d executable=%d expected=%d", counts.KnownOperations, counts.RequestPlansComplete, counts.RuntimeBindingsBound, counts.Admitted, plan.ExecutableOperations(), len(identities))
	}
	return metadata, canaries, plan, root, identities
}

func loadPartialRegistryIdentityFixture(t *testing.T) partialRegistryIdentityFixture {
	t.Helper()
	const fixturePath = "../../testdata/operation-observation-plan/partial-registry-identities.v1.json"
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if digest(raw) != partialRegistryIdentityFixtureSHA256 {
		t.Fatalf("partial-provider identity fixture changed without refreshing its source pin: %s", fixturePath)
	}
	var fixture partialRegistryIdentityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal("could not decode the pinned partial-provider identity fixture:", err)
	}
	if fixture.SchemaVersion != "datapan.health-operation-plan-partial-identities.v1" || fixture.DerivedFromRegistryRevision != "da02fccaee4989c5c6dcf3b60e8e627ecd477cca" || fixture.DerivedFromIndexSHA256 != "31e0cc830161acfd69b2b37956a041e5824862db932c21d1bef235369acd2e17" || len(fixture.SourceScopes) != 4 {
		t.Fatal("partial-provider identity fixture no longer matches its pinned Registry-plan provenance")
	}
	seenSources := make(map[string]struct{}, len(fixture.SourceScopes))
	for _, scope := range fixture.SourceScopes {
		if scope.SourceID == "" || scope.Provider == "" || scope.AdapterID == "" || scope.InventoryStatus != "partial" || !scope.InventoryUnknown || scope.OperationID == "" || scope.Protocol == "" {
			t.Fatalf("partial-provider fixture identity is incomplete or falsely marked as known inventory: source=%q operation=%q", scope.SourceID, scope.OperationID)
		}
		if _, duplicate := seenSources[scope.SourceID]; duplicate {
			t.Fatalf("partial-provider fixture repeats source scope %q", scope.SourceID)
		}
		seenSources[scope.SourceID] = struct{}{}
	}
	return fixture
}

func unknownOperationCount(identities []operationPlanPopulationIdentity) int {
	count := 0
	for _, identity := range identities {
		if identity.InventoryUnknown {
			count++
		}
	}
	return count
}

func populationIdentityMap(identities []operationPlanPopulationIdentity) map[string]operationPlanPopulationIdentity {
	result := make(map[string]operationPlanPopulationIdentity, len(identities))
	for _, identity := range identities {
		result[operationReadModelIdentityKey(identity.SourceID, identity.OperationID)] = identity
	}
	return result
}

func writeManifestDerivedSyntheticPlan(t *testing.T, source RegistryAPIMetadata, metadata VerifiedRegistryAPIMetadata, identities []operationPlanPopulationIdentity, fixture partialRegistryIdentityFixture) (string, OperationObservationPlanBinding) {
	t.Helper()
	root := t.TempDir()
	const restTemplatePath = "../../testdata/operation-observation-plan/synthetic-rest-list.json"
	const soapTemplatePath = "../../testdata/operation-observation-plan/synthetic-soap-read.json"
	templateBytes := map[string][]byte{}
	for name, path := range map[string]string{"REST": restTemplatePath, "SOAP": soapTemplatePath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		templateBytes[name] = raw
	}
	if len(identities) != source.Counts.APIOperations+len(fixture.SourceScopes) {
		t.Fatalf("generated plan identities differ from the pinned Gov-source denominator plus partial-scope fixture: %d != %d+%d", len(identities), source.Counts.APIOperations, len(fixture.SourceScopes))
	}
	// The Gov source artifact is already pinned by api-metadata; this test never
	// copies or fetches the 139 MB Registry source snapshot.
	const govSourcePath = "data/data-go-kr.registry.json"
	govSourceArtifact := operationPlanArtifactRef{Path: govSourcePath, Bytes: source.Source.SizeBytes, SHA256: metadata.sourceDigest()}
	const syntheticInputPrefix = "reports/operation-plan-test"
	inputPaths := []string{
		syntheticInputPrefix + "/generator.py", syntheticInputPrefix + "/operation-manifest.json",
		syntheticInputPrefix + "/legacy-policy.json", syntheticInputPrefix + "/provider-index.json",
		syntheticInputPrefix + "/denominator-a.json", syntheticInputPrefix + "/denominator-b.json",
		syntheticInputPrefix + "/denominator-c.json", syntheticInputPrefix + "/denominator-d.json",
	}
	manifestArtifacts := make([]RegistryReleaseManifestArtifact, 0, len(inputPaths)+len(fixture.SourceScopes)+1+(len(identities)+255)/256+1)
	inputRefs := make([]operationPlanArtifactRef, len(inputPaths))
	for index, path := range inputPaths {
		content := []byte("explicitly synthetic integration-test plan input: " + path)
		sum := digest(content)
		writePlanTestFile(t, root, path, content)
		artifact := RegistryReleaseManifestArtifact{Path: path, Kind: "source", Bytes: int64(len(content)), SHA256: sum}
		if index == 0 {
			artifact.Schema = "text/plain"
		}
		manifestArtifacts = append(manifestArtifacts, artifact)
		inputRefs[index] = operationPlanArtifactRef{Path: path, Bytes: int64(len(content)), SHA256: sum}
	}
	manifestArtifacts = append(manifestArtifacts, RegistryReleaseManifestArtifact{Path: govSourcePath, Kind: "source", Schema: "application/json", Bytes: govSourceArtifact.Bytes, SHA256: govSourceArtifact.SHA256})
	generationInputsRaw, err := json.Marshal(operationObservationPlanGenerationInputs{
		GeneratorPath: inputRefs[0].Path, GeneratorSHA256: inputRefs[0].SHA256,
		OperationManifest: inputRefs[1], LegacyPolicy: inputRefs[2], ProviderIndex: &inputRefs[3],
		OperationDenominators: inputRefs[4:],
	})
	if err != nil {
		t.Fatal(err)
	}

	identitiesBySource := make(map[string][]operationPlanPopulationIdentity)
	sourceIDs := make([]string, 0, 5)
	for _, identity := range identities {
		if _, exists := identitiesBySource[identity.SourceID]; !exists {
			sourceIDs = append(sourceIDs, identity.SourceID)
		}
		identitiesBySource[identity.SourceID] = append(identitiesBySource[identity.SourceID], identity)
	}
	sort.Strings(sourceIDs)
	sourceArtifacts := map[string]operationPlanArtifactRef{"data_go_kr": govSourceArtifact}
	sourceScopes := make([]OperationObservationPlanSourceScope, 0, len(sourceIDs))
	identitySets := make(map[string]*operationIdentitySetHash, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		scopeIdentities := identitiesBySource[sourceID]
		first := scopeIdentities[0]
		set := newOperationIdentitySetHash()
		for _, identity := range scopeIdentities {
			set.add(identity.OperationID)
		}
		identitySets[sourceID] = set
		sourceArtifact := govSourceArtifact
		if sourceID != "data_go_kr" {
			sourceEvidence, err := json.Marshal(map[string]any{
				"test_only": true, "source_id": first.SourceID, "provider": first.Provider, "adapter_id": first.AdapterID,
				"inventory_status": first.InventoryStatus, "inventory_unknown": first.InventoryUnknown,
				"derived_from_registry_revision": fixture.DerivedFromRegistryRevision,
				"derived_from_index_sha256":      fixture.DerivedFromIndexSHA256,
				"identity_fixture_sha256":        partialRegistryIdentityFixtureSHA256,
			})
			if err != nil {
				t.Fatal(err)
			}
			path := syntheticInputPrefix + "/sources/" + sourceID + ".synthetic.json"
			writePlanTestFile(t, root, path, sourceEvidence)
			sourceArtifact = operationPlanArtifactRef{Path: path, Bytes: int64(len(sourceEvidence)), SHA256: digest(sourceEvidence)}
			manifestArtifacts = append(manifestArtifacts, RegistryReleaseManifestArtifact{Path: path, Kind: "source", Schema: "application/json", Bytes: sourceArtifact.Bytes, SHA256: sourceArtifact.SHA256})
		}
		sourceArtifacts[sourceID] = sourceArtifact
		sourceScopes = append(sourceScopes, OperationObservationPlanSourceScope{
			SourceID: first.SourceID, Provider: first.Provider, AdapterID: first.AdapterID,
			InventoryStatus: first.InventoryStatus, InventoryUnknown: first.InventoryUnknown,
			TestOnly: false, RegisteredOperations: len(scopeIdentities), IdentitySetSHA256: set.digest(),
			SourceArtifacts: []operationPlanArtifactRef{sourceArtifact},
		})
	}

	globalQuotaKey := "synthetic-full-population"
	globalQuotaDigest := OperationQuotaScopeDigest("global", globalQuotaKey)
	credentialScopeKey := "synthetic:credential-group:full-population"
	credentialQuotaDigest := OperationQuotaScopeDigest("credential", credentialScopeKey)
	recordsBySource := make(map[string][]json.RawMessage, len(sourceIDs))
	for _, identity := range identities {
		templateName := identity.Protocol
		if templateName == "HTTP" {
			// The execution contract is a local synthetic REST request; it does
			// not claim that the source's protocol label proves API semantics.
			templateName = "REST"
		}
		if templateName != "REST" && templateName != "SOAP" {
			t.Fatalf("synthetic executor does not support source protocol %q for %s/%s", identity.Protocol, identity.SourceID, identity.OperationID)
		}
		var record map[string]any
		if json.Unmarshal(templateBytes[templateName], &record) != nil {
			t.Fatalf("could not decode explicitly synthetic %s contract", templateName)
		}
		sourceBinding := record["source_binding"].(map[string]any)
		sourceBinding["source_id"], sourceBinding["provider"], sourceBinding["adapter_id"] = identity.SourceID, identity.Provider, identity.AdapterID
		sourceBinding["inventory_status"], sourceBinding["inventory_unknown"], sourceBinding["test_only"] = identity.InventoryStatus, identity.InventoryUnknown, false
		operationIdentity := record["operation_identity"].(map[string]any)
		operationIdentity["operation_id"], operationIdentity["protocol"] = identity.OperationID, templateName
		if identity.DatasetID != "" {
			operationIdentity["dataset_id"] = identity.DatasetID
		}
		runtimeBinding := record["runtime_binding"].(map[string]any)
		runtimeBinding["credential_reference"], runtimeBinding["credential_scope_key"] = "test-only/synthetic", credentialScopeKey
		sourceArtifact := sourceArtifacts[identity.SourceID]
		quotaEvidence := map[string]any{"artifact_path": sourceArtifact.Path, "evidence_kind": "reviewed_policy", "json_pointer": "#/synthetic_full_population_quota", "sha256": sourceArtifact.SHA256}
		runtimeBinding["quota_policies"] = []any{
			map[string]any{
				"scope_key": globalQuotaKey, "scope_kind": "global", "scope_sha256": globalQuotaDigest,
				"max_concurrent": 32, "requests_per_window": len(identities), "window_seconds": int64(600),
				"minimum_interval_seconds": int64(0), "evidence_refs": []any{quotaEvidence},
			},
			map[string]any{
				"scope_key": credentialScopeKey, "scope_kind": "credential", "scope_sha256": credentialQuotaDigest,
				"max_concurrent": 32, "requests_per_window": len(identities), "window_seconds": int64(600),
				"minimum_interval_seconds": int64(0), "evidence_refs": []any{quotaEvidence},
			},
		}
		request := record["request_plan"].(map[string]any)
		requestContract := request["request_contract"].(map[string]any)
		transport := requestContract["transport"].(map[string]any)
		transport["protocol"] = templateName
		if templateName == "SOAP" {
			transport["soap_action"] = "urn:synthetic:Read"
			soapParameters := requestContract["parameters"].([]any)
			soapParameters[0].(map[string]any)["qualified_name"] = map[string]any{"namespace": "urn:synthetic:request", "local_name": "RecordID"}
		}
		rewriteGatusEvidence(record, "fixtures/operation-observation-plan/synthetic-source.json", sourceArtifact.Path, sourceArtifact.SHA256, sourceArtifact.Bytes)
		transport["authority"] = "operation_document"
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		recordsBySource[identity.SourceID] = append(recordsBySource[identity.SourceID], encoded)
	}

	shardRefs := make([]operationObservationPlanShardRef, 0, (len(identities)+255)/256+len(sourceIDs))
	for _, sourceID := range sourceIDs {
		scopeIdentities := identitiesBySource[sourceID]
		records := recordsBySource[sourceID]
		for offset, shardIndex := 0, 0; offset < len(scopeIdentities); offset, shardIndex = offset+256, shardIndex+1 {
			end := min(offset+256, len(scopeIdentities))
			shardRecords := append([]json.RawMessage(nil), records[offset:end]...)
			path := fmt.Sprintf("reports/operation-observation-plan/shards/%s-%04d.json", sourceID, shardIndex)
			shardRaw, err := json.Marshal(operationObservationPlanShardWire{SchemaVersion: OperationObservationPlanSchemaVersion, ArtifactKind: "shard", SourceID: sourceID, ShardIndex: shardIndex, Records: shardRecords})
			if err != nil {
				t.Fatal(err)
			}
			writePlanTestFile(t, root, path, shardRaw)
			shardRefs = append(shardRefs, operationObservationPlanShardRef{
				SourceID: sourceID, ShardIndex: shardIndex, Path: path, SHA256: digest(shardRaw), Bytes: int64(len(shardRaw)),
				RecordCount: len(shardRecords), FirstOperationID: scopeIdentities[offset].OperationID, LastOperationID: scopeIdentities[end-1].OperationID,
			})
			manifestArtifacts = append(manifestArtifacts, RegistryReleaseManifestArtifact{Path: path, Kind: "operation_observation_plan_shard", Schema: operationObservationPlanSchemaURI, Bytes: int64(len(shardRaw)), SHA256: digest(shardRaw)})
		}
	}
	const indexPath = "reports/operation-observation-plan/index.json"
	index := operationObservationPlanIndex{
		SchemaVersion: OperationObservationPlanSchemaVersion, ArtifactKind: "index", RegistryRevision: fixture.DerivedFromRegistryRevision,
		GenerationInputs: generationInputsRaw, InventoryContext: operationPlanInventoryContext{},
		Summary: OperationObservationPlanCounts{
			KnownOperations: len(identities), RequestPlansComplete: len(identities), RuntimeBindingsBound: len(identities), Admitted: len(identities),
			InventoryUnknownScopes: len(fixture.SourceScopes),
		},
		SourceScopes: sourceScopes, Shards: shardRefs,
	}
	indexRaw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	writePlanTestFile(t, root, indexPath, indexRaw)
	indexSHA := digest(indexRaw)
	manifestArtifacts = append(manifestArtifacts, RegistryReleaseManifestArtifact{Path: indexPath, Kind: "operation_observation_plan", Schema: operationObservationPlanSchemaURI, Bytes: int64(len(indexRaw)), SHA256: indexSHA})
	manifest := RegistryReleaseManifest{SchemaVersion: "datapan.release-manifest.v1", Artifacts: manifestArtifacts}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	const manifestPath = "release/manifest.json"
	writePlanTestFile(t, root, manifestPath, manifestRaw)
	return root, OperationObservationPlanBinding{
		RegistryRevision: index.RegistryRevision, ReleaseManifestPath: manifestPath, ReleaseManifestBytes: int64(len(manifestRaw)), ReleaseManifestSHA256: digest(manifestRaw),
		IndexPath: indexPath, IndexBytes: int64(len(indexRaw)), IndexSHA256: indexSHA,
		SchemaRegistryRevision: operationObservationSchemaRegistryRevision, SchemaSHA256: operationObservationPlanSchemaSHA256,
	}
}

func (client *schedulerSyntheticGatus) counts() (int, int) {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.pushes, client.readbacks
}
