VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet lint test-rules test-suricata check-sigma fixtures demo clean install

build:
	go build -ldflags "$(LDFLAGS)" -o bin/crumble ./cmd/crumble

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@command -v golangci-lint >/dev/null && golangci-lint run || \
		echo "golangci-lint not installed, ran go vet only"

# Needs yara-python and sigma-cli: pip install yara-python sigma-cli
test-rules:
	python3 scripts/test_rules.py
	sigma check -i rules/sigma

# Needs suricata on PATH (apt install suricata).
test-suricata:
	./scripts/test_suricata.sh

# Regenerates the obfuscated JS fixtures (needs node/npx). Output is committed.
fixtures:
	./scripts/gen-fixtures.sh

# Writes a synthetic C2 capture and decodes it.
demo: build
	./bin/crumble fixture pcap -out demo.pcap
	./bin/crumble pcap demo.pcap

clean:
	rm -rf bin demo.pcap demo.pcapng dump

install: build
	install -Dm755 bin/crumble /usr/local/bin/crumble
