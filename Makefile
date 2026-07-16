RUNTIME_IMAGE ?= datapan-health-runtime:test
ARCHIVE_IMAGE ?= datapan-health-archive:test

.PHONY: test quality build images image-smoke release-oci smoke visual archive-smoke hf-publish-smoke diagnostic-compatibility

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
	go run ./cmd/health-compatibility -health-head "$(HEALTH_HEAD)" -output out/diagnostic-compatibility.json

hf-publish-smoke:
	./scripts/hf-publish-smoke.sh

visual:
	@test -f docs/evidence/status-desktop.png
	@test -f docs/evidence/status-mobile.png
