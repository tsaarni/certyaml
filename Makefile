all: check build

check: test lint

test:
	go test --race -v ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0 run

build:
	CGO_ENABLED=0 go build -v ./cmd/certyaml

install:
	CGO_ENABLED=0 go install -v ./cmd/certyaml

update-modules:
	go get -u -t ./... && go mod tidy
