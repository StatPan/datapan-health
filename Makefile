.PHONY: test quality build smoke visual archive-smoke hf-publish-smoke

test:
	go test ./...

quality:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	docker compose config --quiet

build:
	docker build --tag datapan-health-runner:test .

smoke:
	./scripts/smoke.sh

archive-smoke:
	go test ./internal/archive -count=1

hf-publish-smoke:
	./scripts/hf-publish-smoke.sh

visual:
	@test -f docs/evidence/status-desktop.png
	@test -f docs/evidence/status-mobile.png
