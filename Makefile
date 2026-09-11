.PHONY: help hooks build run air test lint docker-build

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

hooks: ## Enable the repo git hooks (gofmt on pre-commit)
	git config core.hooksPath .githooks

build: ## Build the binary
	go build -o bin/dns-forward .

run: ## Run against config.yaml
	go run . -config config.yaml

air: ## Run with live reload
	go run github.com/air-verse/air@latest -c .air.toml

test: ## Run all tests
	go test ./...

lint: ## Formatting check and go vet
	gofmt -l internal main.go
	go vet ./...

docker-build: ## Build the Docker image
	docker build -t dns-forward:latest .