.PHONY: build test clean run fmt lint

BINARY=panopticon

build:
	go build -o $(BINARY) ./cmd/$(BINARY)

test:
	go test -v -race ./...

test-short:
	go test -short ./...

fmt:
	go fmt ./...

lint:
	go vet ./...

run: build
	./$(BINARY)

run-verbose: build
	./$(BINARY) -config ./config/panopticon.example.yaml

clean:
	rm -f $(BINARY)

install:
	go install ./cmd/$(BINARY)

# CA certificate installation
.PHONY: trust-ca
trust-ca:
	@echo "Install CA: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.local/share/panopticon/panopticon-ca.pem"
	@echo "Then test: curl -x http://localhost:8080 https://example.com"
