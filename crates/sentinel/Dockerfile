# ---- Builder Stage ----
# Compiles the release binary against the full workspace: `sentinel` depends
# on `safenet-core` via a workspace path dependency, so the build
# needs the whole `crates/` tree, not just `crates/sentinel`.
FROM rust:1-slim AS builder
WORKDIR /usr/src/app

# `pkg-config`/`libsqlite3-dev` are needed to link against the system SQLite
# (the workspace's `sqlx` dependency does not enable the `bundled` feature).
RUN apt-get update && apt-get install -y --no-install-recommends \
	libsqlite3-dev \
	pkg-config \
	&& rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release --locked --package sentinel

# ---- Runtime Stage ----
# Slim image with only the compiled binary and the shared libraries it needs:
# `ca-certificates` for TLS to the RPC and sentinel engine endpoints,
# `libsqlite3-0` because the binary links against the
# system SQLite rather than bundling it.
FROM debian:trixie-slim AS runner
WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	libsqlite3-0 \
	&& rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged numeric identity (no login shell, no home directory).
# The image never contains keys, passwords or keystores: those are mounted at
# runtime (see `deploy/sentinel/compose.prod.yaml`).
#
# The data directory is the only place the sentinel writes (its SQLite
# database), so the rest of the root filesystem can be mounted `read_only`.
# It is created here, owned by the runtime user, so a fresh named volume
# inherits that ownership; bind mounts must be chowned to 65532:65532 by the
# operator. `/tmp` (SQLite temp files) should be a tmpfs.
RUN groupadd --system --gid 65532 sentinel \
	&& useradd --system --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sentinel \
	&& install --directory --owner 65532 --group 65532 --mode 0700 /var/lib/safenet/sentinel/data

COPY --from=builder /usr/src/app/target/release/sentinel ./sentinel

USER 65532:65532

# `ENTRYPOINT` (not `CMD`) so that a Kubernetes/`podman kube play` pod spec's
# `args:` (e.g. `--config-file=...`) appends to the binary instead of
# replacing it.
ENTRYPOINT ["./sentinel"]
