.PHONY: build run air

build:
	go build -o bin/domains-resolver .

run:
	go run . -config config.yaml

air:
	go run github.com/air-verse/air@latest -c .air.toml
