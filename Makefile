# Amarre — build reproductible, sans cgo.
#
# CGO_ENABLED=0 est un choix de conception, pas une commodité : il donne un
# binaire statique déployable sur n'importe quelle Debian sans dépendance
# partagée, et il impose modernc.org/sqlite (SQLite réécrit en Go) plutôt
# qu'un binding C. Une surface d'attaque native en moins dans un outil qui
# détient les accès SSH d'un parc entier.

BIN     := amarre
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := CGO_ENABLED=0

.PHONY: all build test vet lint clean install run

all: vet test build

build:
	$(GOFLAGS) go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BIN) ./cmd/amarre

# Compilation croisée : le parc mêle amd64 et arm64.
build-all:
	$(GOFLAGS) GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BIN)-linux-amd64 ./cmd/amarre
	$(GOFLAGS) GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BIN)-linux-arm64 ./cmd/amarre

test:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -rf bin/

run: build
	./bin/$(BIN) serve --config ./amarre.yml
