# localiam — one image for every role: the per-pod credential sidecar
# (`localiam agent`), the auth-terminating proxies (`localiam proxy`) and the
# central verifier (`localiam server`).
#
# Distroless, static, non-root: no package manager, no libc and no userland,
# so there is nothing for a scanner to flag and nothing to exec but the two
# binaries below. Base images are pinned by digest; Dependabot moves the pins.

# Cross-compiles on the build host rather than emulating the target: the Go
# toolchain targets any GOOS/GOARCH natively, so a multi-platform build runs
# no foreign code.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:c95332c2af86b6d89b91bd0500f4b9529ccbd090a0d1855c6d1ceaa142ae8615 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY . .
# Cache mounts rather than a `go mod download` layer: the module graph includes
# the lint tooling, and downloading all of it for two binaries is wasted time.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/localiam ./cmd/localiam
# The gated shell (cmd/sh), installed below at /bin/sh. A second binary rather
# than a subcommand so that `kubectl exec -- /bin/sh` reaches it by the name
# every runbook already uses, and so its size is its own line in the image.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/sh ./cmd/sh

# The distroless `nonroot` variant runs as uid 65532 and carries CA
# certificates, /etc/passwd and tzdata — the few files a static Go binary may
# still reach for.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime
LABEL org.opencontainers.image.title="localiam" \
      org.opencontainers.image.description="Local AWS IAM data-plane auth for Redis, Postgres and Kafka — a test tool" \
      org.opencontainers.image.source="https://github.com/blairham/localiam" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/usr/local/bin/localiam"]
CMD ["server"]

# The published image: GoReleaser's build context holds <os>/<arch>/<binary>
# for the platform being built, so this stage compiles nothing — it ships the
# same binaries as the release archives. See dockers_v2 in .goreleaser.yaml.
FROM runtime AS release
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/localiam /usr/local/bin/localiam
# /bin/sh is a GATED shell, not a general one: it cannot exec anything, ever,
# and its reads are bounded to /proc and /sys/fs/cgroup, with /proc/*/environ
# denied. That is what makes it a different decision from adding busybox. See
# internal/shell/README.md.
COPY ${TARGETOS}/${TARGETARCH}/sh /bin/sh

# Default: built from source (`make image`, CI). Last, so a bare
# `docker build .` gets it.
FROM runtime
COPY --from=build /out/localiam /usr/local/bin/localiam
COPY --from=build /out/sh /bin/sh
