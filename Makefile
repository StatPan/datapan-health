RUNTIME_IMAGE ?= datapan-health-runtime:test
ARCHIVE_IMAGE ?= datapan-health-archive:test
TESTED_REVISION ?= $(HEALTH_HEAD)

.PHONY: test quality build images image-smoke release-oci smoke visual archive-smoke hf-publish-smoke diagnostic-compatibility assertion-policy-compatibility correlation-replay diagnosis-snapshot-evidence public-status-doctor manifest-verify schedule-coverage schedule-coverage-doctor

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

image-smoke: images
	RUNTIME_IMAGE=$(RUNTIME_IMAGE) ARCHIVE_IMAGE=$(ARCHIVE_IMAGE) ./scripts/image-smoke.sh

release-oci:
	./scripts/build-release-oci.sh

smoke:
	./scripts/smoke.sh

archive-smoke:
	go test ./internal/archive -count=1

diagnostic-compatibility:
	test -n "$(HEALTH_HEAD)"
	go run ./cmd/health-compatibility -health-head "$(HEALTH_HEAD)" -tested-revision "$(TESTED_REVISION)" -output out/diagnostic-compatibility.json

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

hf-publish-smoke:
	./scripts/hf-publish-smoke.sh

visual:
	@test -f docs/evidence/status-desktop.png
	@test -f docs/evidence/status-mobile.png
