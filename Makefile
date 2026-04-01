.PHONY: all build clean proto test vet lint check-secrets check-config ci

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

CAGE_INTERNAL := cage-init payload-proxy findings-sidecar

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

check-config:
	$(GO) run scripts/check_config.go

ci: vet lint check-secrets check-config test build

tidy:
	$(GO) mod tidy

migrate-up:
	@echo "Applying migrations to $(DATABASE_URL)..."
	@for f in migrations/*.sql; do \
		echo "Applying $$f..."; \
		psql "$(DATABASE_URL)" -f "$$f"; \
	done
