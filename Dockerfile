# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------------
# One build stage, cross-compiled: the suite below runs on the builder's
# own platform, once, and the per-platform output is only the build step.
# TARGETARCH is what buildx sets per requested platform (amd64, arm64).
# A plain docker build leaves it empty, and Go then falls back to the
# builder's own architecture, which is the single-platform behaviour.
FROM golang:1.23-alpine AS build

WORKDIR /src

# Dependencies first so edits to our own code do not re-download modules.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# CGO off produces a static binary that runs on any Linux, including a Pi.
# -trimpath keeps build paths out of the binary; the version is injected.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/filebrowser ./cmd/filebrowser

# Run the tests against the same toolchain before shipping. This step has
# no TARGETARCH in it, deliberately: the test binaries always run on the
# builder natively and their result is shared by both platforms.
RUN go vet ./... && go test ./...

# ---- runtime --------------------------------------------------------------
FROM alpine:3.20

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
