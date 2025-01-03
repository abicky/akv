NAME := akv
SRCS := $(shell find . -type f -name '*.go' -not -name '*_test.go' -not -path './internal/testing/*')

all: bin/$(NAME)

bin/$(NAME): $(SRCS)
	go build -o bin/$(NAME)

.PHONY: clean
clean:
	rm -rf bin/$(NAME)

.PHONY: install
install:
	go install -trimpath -ldflags "-s -w -X github.com/abicky/akv/cmd.revision=$(shell git rev-parse --short HEAD)"

.PHONY: test
test:
	go test -v ./...

.PHONY: vet
vet:
	go vet ./...

mock:
	go generate ./...
