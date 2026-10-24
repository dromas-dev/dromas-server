# irongalld, the irongall.dev server: a static binary on Debian slim.
#
# go.mod replaces irongall-client with ../irongall-client, so the build needs
# that checkout too: pass it as the build context named "client"
# (docker build --build-context client=../irongall-client .).
FROM golang:1.27.3-trixie AS build
WORKDIR /src/irongall-server
COPY --from=client go.mod go.sum /src/irongall-client/
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY --from=client . /src/irongall-client
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /irongalld ./cmd/irongalld

# The echo box: a CLIENT, irongall-echo from irongall-client,
# with the irongall command beside it for the operator (addr, adopt). Built only
# as the target "echo"; the default target, the last stage, is the server.
FROM build AS echo-build
WORKDIR /src/irongall-client
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/ ./cmd/irongall-echo ./cmd/irongall

FROM debian:13.7-slim AS echo
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=echo-build /out/irongall-echo /out/irongall /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["irongall-echo"]

# A deployment's site, which serve -site /site serves: empty here, since no
# site is in this repo. A build context named "site" replaces this stage
# (docker build --build-context site=<a directory of rendered pages> .).
FROM scratch AS site

# Debian slim, an exact tag, so a check for base-image updates can follow it.
# Nothing runs in it but the binary, as uid 65532; the CA bundle comes from
# the build stage, for TLS to AWS.
FROM debian:13.7-slim
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /irongalld /irongalld
COPY --from=site / /site/
USER 65532:65532
ENTRYPOINT ["/irongalld", "serve"]
