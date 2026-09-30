.PHONY: build test lint clean install

APP_NAME := iris
VERSION := 1.2.0
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X github.com/Pixelcity-dev/Iris/internal/cli.version=$(VERSION) -X github.com/Pixelcity-dev/Iris/internal/cli.buildTime=$(BUILD_TIME) -X github.com/Pixelcity-dev/Iris/internal/cli.commit=$(COMMIT)"

.PHONY: all
all: build

.PHONY: build
build:
	go build $(LDFLAGS) -o bin/$(APP_NAME) ./cmd/iris

.PHONY: build-dashboard
build-dashboard:
	cd dashboard && go build -ldflags="-s -w" -o ../bin/iris-dashboard .

.PHONY: build-all
build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(APP_NAME)-linux-amd64 ./cmd/iris
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(APP_NAME)-linux-arm64 ./cmd/iris
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(APP_NAME)-darwin-amd64 ./cmd/iris
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(APP_NAME)-darwin-arm64 ./cmd/iris
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(APP_NAME)-windows-amd64.exe ./cmd/iris

.PHONY: install
install:
	go install $(LDFLAGS) ./cmd/iris

.PHONY: test
test:
	go test -v ./...

.PHONY: test-dashboard
test-dashboard:
	cd dashboard && go test ./...

.PHONY: test-cover
test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: vet
vet:
	go vet ./...

.PHONY: clean
clean:
	rm -rf bin/ dist/ coverage.out coverage.html

.PHONY: docker-build
docker-build:
	docker build -t deepsec:$(VERSION) -f docker/Dockerfile .

.PHONY: docker-run
docker-run:
	docker run --rm deepsec:$(VERSION)

.PHONY: init
init:
	go mod tidy
