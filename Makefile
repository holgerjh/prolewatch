.PHONY: build test vet check-layering probes acceptance-probes acceptance-vm security-test scenarios installed-scenarios release-check release-aur dev-install arch-package arch-package-clean verify-arch-package clean

build:
	./scripts/build.sh

test:
	go test -race ./...

vet:
	go vet ./...

check-layering:
	./scripts/check-import-direction.sh

probes:
	./scripts/run-probes.sh

# Release acceptance: a probe that skips is a failure. Run on the disposable
# Arch system where Prolewatch is installed, not in a source tree.
acceptance-probes:
	PROLEWATCH_PROBE_STRICT=1 ./scripts/run-probes.sh

# Creates and drives the disposable Arch VM used for installed acceptance.
acceptance-vm:
	./scripts/acceptance-vm.sh

security-test:
	go test -race ./internal/audit

scenarios:
	go run ./cmd/prolewatch-scenarios

installed-scenarios:
	go run ./cmd/prolewatch-scenarios --installed

release-check:
	./scripts/release-check.sh

release-aur:
	./scripts/release-aur.sh "$(VERSION)"

# Key ceremony, build, verify, and install in one step. Idempotent: the signing
# key is created once and reused, which is what makes it usable on a disposable
# acceptance system.
dev-install:
	./scripts/dev-install.sh

arch-package:
	./scripts/build-arch-package.sh

arch-package-clean:
	PROLEWATCH_ARCH_CLEAN=1 ./scripts/build-arch-package.sh

verify-arch-package:
	./scripts/verify-arch-package.sh "$(PACKAGE)"

clean:
	rm -rf -- build
