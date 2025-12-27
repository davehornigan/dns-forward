.PHONY: build run air

build:
	go build -o bin/domains-resolver .

run:
	go run . -config config.yaml

air:
	go run -mod=mod github.com/air-verse/air -c .air.toml
