.PHONY: all build clean proto test vet lint check-secrets check-checksums checksums ci

GO := go
GOFLAGS := -trimpath
BINDIR := bin

all: vet build

build: build-agentcage build-cage-internal

build-agentcage:
	$(GO) build $(GOFLAGS) -o $(BINDIR)/agentcage ./cmd/agentcage/

build-linux-vm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BINDIR)/vm/agentcage-linux-arm64 ./cmd/agentcage/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINDIR)/vm/agentcage-linux-amd64 ./cmd/agentcage/

build-vm-rootfs:
	./scripts/build-vm-rootfs.sh $(BINDIR)/vm/rootfs-$(shell uname -m).img

build-cage-rootfs: build-cage-internal
	./scripts/build-cage-rootfs.sh $(BINDIR)/cage-rootfs-$(shell uname -m).ext4

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
	golangci-lint run ./...

check-secrets:
	$(GO) run scripts/check_secret_redaction.go

checksums:
	./scripts/embed-checksums.sh $(ASSETS_DIR)

check-checksums:
	$(GO) run scripts/check_checksums.go $(ASSETS_DIR)

ci: vet lint check-secrets test build

tidy:
	$(GO) mod tidy

migrate-up:
	@echo "Applying migrations to $(DATABASE_URL)..."
	@for f in migrations/*.sql; do \
		echo "Applying $$f..."; \
		psql "$(DATABASE_URL)" -f "$$f"; \
	done
