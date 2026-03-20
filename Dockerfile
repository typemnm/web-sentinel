# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Builder
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1.78-slim-bookworm AS builder

# System libs required by vendored crates (mlua, rusqlite, headless_chrome)
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency layer: copy manifests first, build deps only
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs \
    && cargo build --release 2>/dev/null || true \
    && rm -rf src

# Build actual source
COPY src ./src
COPY sentinel.toml ./
# Touch main.rs so cargo detects the change
RUN touch src/main.rs && cargo build --release

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Runtime
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Runtime deps: Chromium (for headless browser XSS checks), CA certs
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for least privilege
RUN useradd -m -u 1000 sentinel

WORKDIR /app

# Binary
COPY --from=builder /build/target/release/sentinel /usr/local/bin/sentinel

# Default config + example Lua scripts
COPY sentinel.toml ./
COPY scripts ./scripts

# Results output directory (bind-mount or named volume in practice)
RUN mkdir -p /app/output && chown -R sentinel:sentinel /app

USER sentinel

VOLUME ["/app/output", "/app/scripts"]

ENTRYPOINT ["sentinel"]
CMD ["--help"]
