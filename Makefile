.PHONY: test quality build smoke

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
