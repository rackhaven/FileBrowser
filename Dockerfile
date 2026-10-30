# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------------
# One build stage, cross-compiled. --platform=$BUILDPLATFORM keeps the stage
# on the builder's own architecture for every requested platform, so nothing
# runs under emulation; only the final go build differs per platform. Without
# it, buildx ran the whole stage, tests included, under QEMU for arm64.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine3.24 AS build

WORKDIR /src

# Dependencies first so edits to our own code do not re-download modules.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Run the tests against the same toolchain before shipping. This step comes
# before TARGETARCH is declared, deliberately: nothing above it differs per
# platform, so buildx runs it once, natively, and every platform shares the
# result.
RUN go vet ./... && go test ./...

# TARGETARCH is what buildx sets per requested platform (amd64, arm64). It
# must be declared inside the stage to be visible here. A plain docker build
# leaves it empty, and Go then builds for the builder's own architecture.
# CGO off produces a static binary that runs on any Linux, including a Pi.
# -trimpath keeps build paths out of the binary; the version is injected.
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/filebrowser ./cmd/filebrowser

# ---- runtime --------------------------------------------------------------
FROM alpine:3.24

# ca-certificates is needed so the server can reach a Let's Encrypt renewal
# endpoint when TLS is terminated here rather than at a proxy.
# tzdata lets folder listings render local time rather than UTC.
RUN apk add --no-cache ca-certificates tzdata wget \
 && adduser -D -H -u 10001 filebrowser

COPY --from=build /out/filebrowser /usr/local/bin/filebrowser

# /srv/files is the default root. Mount your own storage here.
RUN mkdir -p /srv/files /data \
 && chown -R filebrowser:filebrowser /srv/files /data

USER filebrowser:filebrowser

ENV FB_LISTEN=0.0.0.0:8080 \
    FB_ROOT=/srv/files \
    FB_DATA_DIR=/data \
    FB_LOG_LEVEL=info

EXPOSE 8080
VOLUME ["/srv/files", "/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["filebrowser"]
