# ---------------------------------------------------------------------------
# Minimal 3desco image. Two stages:
#
#   1. build a fully static musl binary with the alpine rust toolchain. every
#      dependency (clap, hex, des, cbc) is pure Rust, so there is no OpenSSL or
#      other C library to link -- the result is a self-contained executable.
#   2. copy just that binary into `scratch`. the final image is the binary and
#      nothing else: no shell, no package manager, a few megabytes total.
#
# entrypoint is the app itself, so `docker run ghcr.io/wiggels/3desco <value>`
# behaves exactly like the local `3desco <value>`.
# ---------------------------------------------------------------------------
FROM rust:1-alpine AS builder

# musl-dev provides the crt objects the static link needs
RUN apk add --no-cache musl-dev

WORKDIR /app

# copy manifests first so a dependency-only layer caches across source edits
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# --locked pins to Cargo.lock; strip drops symbols for a smaller binary
RUN cargo build --release --locked \
    && strip target/release/3desco

# ---------------------------------------------------------------------------
FROM scratch

COPY --from=builder /app/target/release/3desco /3desco

ENTRYPOINT ["/3desco"]
