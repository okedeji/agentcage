.PHONY: all build build-agentcage build-linux-vm build-vm-rootfs build-cage-rootfs \
       build-cage-internal build-typescript-sdk clean proto test vet lint \
       check-secrets check-checksums checksums ci tidy

GO := go
VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo dev)
LDFLAGS := -X main.version=$(VERSION:v%=%)
GOFLAGS := -trimpath -ldflags '$(LDFLAGS)'
BINDIR := bin

all: vet build

build: build-agentcage build-cage-internal

build-agentcage:
	$(GO) build $(GOFLAGS) -o $(BINDIR)/agentcage ./cmd/agentcage/
ifeq ($(shell uname),Darwin)
	codesign --entitlements entitlements.plist --force -s - $(BINDIR)/agentcage
endif

# Go uses GOARCH=arm64 on both macOS and Linux. uname -m returns
# arm64 on macOS but aarch64 on Linux; normalize to Go convention.
GOARCH_ARM := arm64
GOARCH_AMD := amd64

build-linux-vm:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH_ARM) $(GO) build $(GOFLAGS) -o $(BINDIR)/vm/agentcage-linux-$(GOARCH_ARM) ./cmd/agentcage/
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH_AMD) $(GO) build $(GOFLAGS) -o $(BINDIR)/vm/agentcage-linux-$(GOARCH_AMD) ./cmd/agentcage/

# Normalize uname -m to Go arch for rootfs naming.
UNAME_ARCH := $(shell uname -m)
ifeq ($(UNAME_ARCH),x86_64)
  NORMALIZED_ARCH := amd64
else ifeq ($(UNAME_ARCH),aarch64)
  NORMALIZED_ARCH := arm64
else
  NORMALIZED_ARCH := $(UNAME_ARCH)
endif

build-vm-rootfs:
	./scripts/build-vm-rootfs.sh $(BINDIR)/vm/rootfs-$(NORMALIZED_ARCH).img

build-cage-rootfs: build-cage-internal
	./scripts/build-cage-rootfs.sh $(BINDIR)/cage-rootfs-$(NORMALIZED_ARCH).ext4

CAGE_INTERNAL := cage-init payload-proxy findings-sidecar directive-sidecar

build-cage-internal: $(addprefix build-cage-internal-,$(CAGE_INTERNAL))

build-cage-internal-%:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BINDIR)/cage-internal/$* ./cmd/cage-internal/$*/

clean:
	rm -rf $(BINDIR)

proto:
	@echo "Generating proto stubs..."
	protoc \
		--proto_path=. \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/*.proto

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "error: golangci-lint not found (install: https://golangci-lint.run/welcome/install/)"; exit 1; }
	golangci-lint run ./...

check-secrets:
	$(GO) run scripts/check_secret_redaction.go

checksums:
	./scripts/embed-checksums.sh $(ASSETS_DIR)

check-checksums:
	$(GO) run scripts/check_checksums.go $(ASSETS_DIR)

ci: vet lint check-secrets test build

build-typescript-sdk:
	cd sdk/typescript && npm install && npm run build

tidy:
	$(GO) mod tidy
