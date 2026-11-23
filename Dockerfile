# syntax=docker/dockerfile:1

# Global build arg — must be declared before the first FROM to be usable in any
# FROM line (overridable via --build-arg GOLANG_VERSION=...).
ARG GOLANG_VERSION=1.25

# --- Build stage ---
FROM golang:${GOLANG_VERSION}-alpine AS builder

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOFLAGS="-mod=readonly"

WORKDIR /src

# Dependency caching: copy manifests first.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# Source (build context is trimmed by .dockerignore).
COPY . .

# Release tag baked into the binary (main.version), logged at startup.
ARG APP_VERSION=dev

# -trimpath removes local filesystem paths; -s -w strips the symbol table and
# DWARF for a smaller artifact. The timetzdata tag embeds the zoneinfo database,
# which the runtime image does not carry, so TZ=... still resolves in logs.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -tags timetzdata -ldflags="-s -w -X main.version=${APP_VERSION}" -o /out/dns-forward .

# --- Runtime image ---
# distroless/static: only CA certificates (needed by the DoT/DoH upstreams) and
# /etc/passwd. No shell, no package manager, no libc — minimal attack surface.
#
# Deliberately NOT the :nonroot variant: the default listenAddr is :53, and an
# unprivileged user cannot bind a port below 1024 without CAP_NET_BIND_SERVICE.
# Drop to nonroot in your own deployment if you listen on a high port.
FROM gcr.io/distroless/static-debian12 AS runtime

WORKDIR /app

COPY --from=builder /out/dns-forward /usr/local/bin/dns-forward

EXPOSE 53/udp
EXPOSE 53/tcp

ENTRYPOINT ["/usr/local/bin/dns-forward"]
CMD ["-config", "config.yaml"]
