# dromasd, the dromas.dev server: a static binary on Debian slim.
#
# go.mod replaces dromas-client with ../dromas-client, so the build needs
# that checkout too: pass it as the build context named "client"
# (docker build --build-context client=../dromas-client .).
#
# The Go stages run on the builder's own platform and cross-compile for the
# target's (docker build --platform linux/amd64,linux/arm64), so no stage
# runs under emulation: the images they are copied into only copy.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie AS build
WORKDIR /src/dromas-server
COPY --from=client go.mod go.sum /src/dromas-client/
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY --from=client . /src/dromas-client
COPY . .
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /dromasd ./cmd/dromasd

# Debian slim, an exact tag, so a check for base-image updates can follow it.
# Nothing runs in it but the binary, as uid 65532; the CA bundle comes from
# the build stage, for TLS to AWS.
FROM debian:13.7-slim
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /dromasd /dromasd
USER 65532:65532
ENTRYPOINT ["/dromasd", "serve"]
