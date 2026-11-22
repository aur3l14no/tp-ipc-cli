BINARY := tp-ipc
VERSION ?= 0.4.0
LDFLAGS := -s -w -X main.version=$(VERSION)

PLATFORMS := \
	darwin/arm64 \
	darwin/amd64 \
	linux/arm64 \
	linux/amd64

.PHONY: build test dist clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/tp-ipc

test:
	CGO_ENABLED=0 go test -v ./...

dist:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		out="dist/$(BINARY)-$${os}-$${arch}"; \
		echo "Building $$out ..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" ./cmd/tp-ipc || exit 1; \
	done
	@cd dist && shasum -a 256 $(BINARY)-* > SHA256SUMS

clean:
	rm -rf $(BINARY) dist
