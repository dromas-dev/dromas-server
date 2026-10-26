# dromasd, the dromas.dev server: a static binary on Debian slim.
#
# The Go stages run on the builder's own platform and cross-compile for the
# target's (docker build --platform linux/amd64,linux/arm64), so no stage
# runs under emulation: the images they are copied into only copy.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS build
WORKDIR /src/dromas-server
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /dromasd ./cmd/dromasd

# Debian slim. Each base image is an exact tag and its index digest, which
# Dependabot moves together.
# Nothing runs in it but the binary, as uid 65532; the CA bundle comes from
# the build stage, for TLS to AWS.
FROM debian:13.7-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /dromasd /dromasd
USER 65532:65532
ENTRYPOINT ["/dromasd", "serve"]
