RUNTIME_IMAGE ?= datapan-health-runtime:test
ARCHIVE_IMAGE ?= datapan-health-archive:test
TESTED_REVISION ?= $(HEALTH_HEAD)

.PHONY: test quality build images image-smoke release-oci release-governance-smoke release-provenance-smoke runtime-publication-contract smoke visual archive-smoke hf-publish-smoke governance-check security-reporting-check security-reporting-check-test diagnostic-compatibility diagnostic-provenance diagnostic-provenance-check assertion-policy-compatibility correlation-replay diagnosis-snapshot-evidence public-status-doctor manifest-verify schedule-coverage schedule-coverage-doctor operation-plan-full-population operation-plan-gatus-integration operation-plan-gatus-capacity operation-plan-actual-cli-smoke operation-plan-actual-cli-full

test:
	go test ./...

quality:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	docker compose config --quiet

build:
	docker build --target runtime --tag $(RUNTIME_IMAGE) .

images:
	docker build --target runtime --tag $(RUNTIME_IMAGE) .
	docker build --target archive --tag $(ARCHIVE_IMAGE) .

image-smoke: images release-governance-smoke
	RUNTIME_IMAGE=$(RUNTIME_IMAGE) ARCHIVE_IMAGE=$(ARCHIVE_IMAGE) ./scripts/image-smoke.sh

release-oci: governance-check release-governance-smoke release-provenance-smoke
	./scripts/build-release-oci.sh

smoke:
	./scripts/smoke.sh

archive-smoke:
	go test ./internal/archive -count=1

diagnostic-compatibility:
	test -n "$(HEALTH_HEAD)"
	go run ./cmd/health-compatibility -health-head "$(HEALTH_HEAD)" -tested-revision "$(TESTED_REVISION)" -output out/diagnostic-compatibility.json

diagnostic-provenance:
	go run ./cmd/health-diagnostic-provenance

diagnostic-provenance-check:
	go run ./cmd/health-diagnostic-provenance -check

assertion-policy-compatibility:
	test -n "$(HEALTH_HEAD)"
	go run ./cmd/health-assertion-compatibility -health-head "$(HEALTH_HEAD)" -tested-revision "$(TESTED_REVISION)" -output out/assertion-policy-compatibility.json

correlation-replay:
	mkdir -p out
	go run ./cmd/health-correlation -replay testdata/correlation/observed-notice.json > out/correlation-replay.json

diagnosis-snapshot-evidence:
	test -n "$(HEALTH_HEAD)"
	mkdir -p out
	go run ./cmd/health-diagnosis-project -correlation-replay testdata/correlation/observed-notice.json -health-head "$(HEALTH_HEAD)" -tested-revision "$(TESTED_REVISION)" -output out/public-diagnosis-snapshot.json -receipt-output out/diagnosis-projector-receipt.json
	go run ./cmd/health-diagnosis-doctor -snapshot out/public-diagnosis-snapshot.json -at 2026-07-17T00:15:00Z > out/diagnosis-doctor.json

public-status-doctor:
	go run ./cmd/health-public -doctor

manifest-verify:
	go run ./cmd/health-manifest-verify

schedule-coverage:
	mkdir -p out
	go run ./cmd/health-schedule-coverage -at 2026-07-23T00:00:00Z -shards 64 -state out/schedule-coverage-state.json -output out/schedule-coverage.json

schedule-coverage-doctor: schedule-coverage
	go run ./cmd/health-public -doctor -schedule-coverage-state out/schedule-coverage-state.json -schedule-coverage-reference-at 2026-07-23T00:00:00Z > out/schedule-coverage-doctor.json

# Explicit synthetic source-QA fixture: 12,662 pinned Gov metadata identities
# plus four explicit partial-provider fixture identities. This is not a claim
# to enumerate the whole Registry population; it never contacts providers.
# The 55-minute Go test bound contains a measured 45-minute controller budget;
# virtual pass timestamps do not establish production scheduling cadence.
operation-plan-full-population:
	HEALTH_OPERATION_FULL_POPULATION_TEST=1 go test ./internal/health -run '^TestOperationPlanManifestDerivedSyntheticPopulation$$' -count=1 -timeout=55m -v

# Starts the exact pinned Gatus image on loopback and verifies one synthetic
# receipt through the production push/readback adapter. No provider is called.
operation-plan-gatus-integration:
	HEALTH_OPERATION_GATUS_INTEGRATION_TEST=1 go test ./internal/health -run '^TestOperationPlanPinnedGatusSyntheticReceiptIntegration$$' -count=1 -timeout=5m

# Loads the same generated fixture identity mapping into pinned Gatus and
# verifies bounded exact-key push/readback samples without provider URLs.
operation-plan-gatus-capacity:
	HEALTH_OPERATION_GATUS_CAPACITY_TEST=1 go test ./internal/health -run '^TestOperationPlanPinnedGatusManifestCapacity$$' -count=1 -timeout=20m -v

# Production child runner against an isolated local synthetic provider and
# pinned Gatus. Smoke validates protocol fixtures; full runs the bounded
# manifest-derived source-QA population. Neither mode contacts real providers.
operation-plan-actual-cli-smoke:
	HEALTH_OPERATION_ACTUAL_CLI_MODE=smoke go test ./internal/health -run '^TestOperationPlanActualCLIProviderGatusIntegration$$' -count=1 -timeout=15m -v

# Runs a bounded 1,024-task diagnostic through the production worker path.
# Its aggregate errors are diagnostic only and do not establish fleet readiness.
operation-plan-actual-cli-diagnostic:
	HEALTH_OPERATION_ACTUAL_CLI_MODE=diagnostic go test ./internal/health -run '^TestOperationPlanActualCLIProviderGatusIntegration$$' -count=1 -timeout=20m -v

operation-plan-actual-cli-full:
	HEALTH_OPERATION_ACTUAL_CLI_MODE=full go test ./internal/health -run '^TestOperationPlanActualCLIProviderGatusIntegration$$' -count=1 -timeout=120m -v

hf-publish-smoke:
	./scripts/hf-publish-smoke.sh

governance-check:
	./scripts/check-governance.sh

security-reporting-check:
	./scripts/check-private-vulnerability-reporting.sh

security-reporting-check-test:
	./scripts/check-private-vulnerability-reporting-test.sh

release-governance-smoke:
	./scripts/release-governance-smoke.sh

release-provenance-smoke:
	./scripts/release-provenance-smoke.sh

runtime-publication-contract:
	./scripts/check-runtime-publication-workflow.sh

visual:
	@test -f docs/evidence/status-desktop.png
	@test -f docs/evidence/status-mobile.png
