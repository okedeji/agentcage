.PHONY: all build clean proto test vet lint check-secrets check-config ci

GO := go
GOFLAGS := -trimpath
BINDIR := bin

CMDS := orchestrator payload-proxy findings-sidecar cage-cli

all: vet build

build: $(addprefix build-,$(CMDS))

build-%:
	$(GO) build $(GOFLAGS) -o $(BINDIR)/$* ./cmd/$*/

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

ci: vet check-secrets check-config test build

tidy:
	$(GO) mod tidy

migrate-up:
	@echo "Applying migrations to $(DATABASE_URL)..."
	@for f in migrations/*.sql; do \
		echo "Applying $$f..."; \
		psql "$(DATABASE_URL)" -f "$$f"; \
	done
