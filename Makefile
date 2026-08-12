.PHONY: build test vet security-test scenarios installed-scenarios release-check clean

build:
	./scripts/build.sh

test:
	go test -race ./...

vet:
	go vet ./...

security-test:
	go test -race ./internal/audit

scenarios:
	go run ./cmd/prolewatch-scenarios

installed-scenarios:
	go run ./cmd/prolewatch-scenarios --installed

release-check:
	./scripts/release-check.sh

clean:
	rm -rf -- build
