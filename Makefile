VERSION ?= 0.1.2
BINARY ?= silo-plugin-auth-oidc

.PHONY: test build manifest clean

test:
	go test ./...

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) .

manifest: build
	./bin/$(BINARY) manifest

clean:
	rm -rf bin dist
