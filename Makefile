.PHONY: all build clean proto test vet lint

GO := go
GOFLAGS := -trimpath
BINDIR := bin

CMDS := orchestrator llm-gateway payload-proxy findings-sidecar cage-cli

all: vet build

build: $(addprefix build-,$(CMDS))

build-%:
	$(GO) build $(GOFLAGS) -o $(BINDIR)/$* ./cmd/$*/

clean:
	rm -rf $(BINDIR)

proto:
	@echo "Generating proto stubs..."
	protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/*.proto

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

tidy:
	$(GO) mod tidy

migrate-up:
	@echo "Applying migrations to $(DATABASE_URL)..."
	@for f in migrations/*.sql; do \
		echo "Applying $$f..."; \
		psql "$(DATABASE_URL)" -f "$$f"; \
	done
