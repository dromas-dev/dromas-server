# dromas-server, the dromas.dev server: the static binary GoReleaser builds, on
# distroless static, which holds the CA bundle, tzdata and the user nonroot
# (uid 65532). Nothing is compiled here, as GoReleaser's dockers_v2 has it:
# this file copies the binary from a context laid out as <os>/<arch>/dromas-server,
# which GoReleaser makes for a release (.goreleaser.yaml) and
# docker-publish.yml makes from a snapshot build on main. With only FROM and
# COPY, no stage runs under emulation for the other platform.
#
# The base is a tag and its index digest, the digest moved by Dependabot,
# each signed by distroless (cosign verify … --certificate-identity
# keyless@distroless.iam.gserviceaccount.com --certificate-oidc-issuer
# https://accounts.google.com).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/dromas-server /dromas-server
USER 65532:65532
ENTRYPOINT ["/dromas-server", "serve"]
