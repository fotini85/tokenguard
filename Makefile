GOFMT := $(shell go env GOROOT)/bin/gofmt


# Run `make` with no target for the list.
.DEFAULT_GOAL := help

.PHONY: help build test race vet fmt lint bench db-up db-down db-shell migrate run clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Compile everything
	go build ./...

test: ## Run tests
	go test ./...

race: ## Run tests under the race detector
	go test -race -count=1 ./...

vet: ## Run go vet
	go vet ./...


fmt: ## Check formatting
	@out=$$($(GOFMT) -l ./cmd ./internal); \
	if [ -n "$$out" ]; then echo "not formatted:"; echo "$$out"; exit 1; fi	
 

lint: fmt vet ## Formatting and vet together

bench: ## Run benchmarks with allocation counts
	go test -run '^$$' -bench . -benchmem ./...

check: lint race ## What CI runs

db-up: ## Start Postgres in Docker, bound to localhost only
	docker run --name tg-pg \
		-e POSTGRES_PASSWORD=dev \
		-e POSTGRES_DB=tokenguard \
		-p 127.0.0.1:5432:5432 \
		-d postgres:16 || docker start tg-pg
	@echo "waiting for postgres..."
	@until docker exec tg-pg pg_isready -U postgres -q 2>/dev/null; do sleep 0.3; done
	@echo "ready"

db-down: ## Stop and remove the container, losing its data
	docker rm -f tg-pg

db-shell: ## Open psql
	docker exec -it tg-pg psql -U postgres -d tokenguard

migrate: ## Apply the schema
	docker exec -i tg-pg psql -U postgres -d tokenguard < migrations/001_init.sql

run: ## Start the demo server
	go run ./cmd/demo

clean: ## Remove build artefacts and test cache
	go clean -testcache
	rm -rf bin/