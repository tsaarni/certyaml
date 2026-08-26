all: check build

check: test lint

test:
	go test --race -v ./...

lint:
	go tool -modfile=tools/go.mod golangci-lint run

build:
	CGO_ENABLED=0 go build -v ./cmd/certyaml

install:
	CGO_ENABLED=0 go install -v ./cmd/certyaml

update-modules:
	go get -u -t ./... && go mod tidy
