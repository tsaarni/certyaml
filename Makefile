all: check build

test:
	go test -v ./...

check: test
	golangci-lint run
	gosec -quiet ./..

build:
	go build -v ./cmd/certyaml

install:
	go install -v ./cmd/certyaml

install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.42.1
	go install github.com/securego/gosec/v2/cmd/gosec@v2.9.2

update-modules:
	go get -u -t ./... && go mod tidy
