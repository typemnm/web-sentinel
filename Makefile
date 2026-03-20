.PHONY: build release test lint fmt clean install docker docker-run

BINARY  := sentinel
INSTALL := /usr/local/bin/$(BINARY)

# ─────────────────────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────────────────────

build:
	cargo build

release:
	cargo build --release
	@echo "Binary: target/release/$(BINARY)  ($$(du -sh target/release/$(BINARY) | cut -f1))"

# ─────────────────────────────────────────────────────────────────────────────
# Quality
# ─────────────────────────────────────────────────────────────────────────────

test:
	cargo test --locked

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

check: fmt-check lint test

# ─────────────────────────────────────────────────────────────────────────────
# Install / Uninstall
# ─────────────────────────────────────────────────────────────────────────────

install: release
	install -m 0755 target/release/$(BINARY) $(INSTALL)
	@echo "Installed to $(INSTALL)"

uninstall:
	rm -f $(INSTALL)
	@echo "Removed $(INSTALL)"

# ─────────────────────────────────────────────────────────────────────────────
# Docker
# ─────────────────────────────────────────────────────────────────────────────

docker:
	docker build -t sentinel:latest .

docker-run:
	docker run --rm \
	    -v "$(PWD)/output:/app/output" \
	    -v "$(PWD)/scripts:/app/scripts" \
	    sentinel:latest $(ARGS)

# Example: make scan TARGET=https://example.com
scan: release
	./target/release/$(BINARY) --target $(TARGET) --output output/result.json

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────────

clean:
	cargo clean
	rm -rf output/*.json output/*.sled
