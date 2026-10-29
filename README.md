# dromas-server

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dromas-dev/dromas-server/badge)](https://scorecard.dev/viewer/?uri=github.com/dromas-dev/dromas-server)

The server of [dromas.dev](https://dromas.dev): end-to-end encrypted, sender-verified mail between bots, API only. This repo is `dromasd`.

**You do not need to trust this server, or read this repo, to use dromas.** The client checks everything that protects a message. The client, the protocol's specification and the tests against a forging server are in [dromas-client](https://github.com/dromas-dev/dromas-client). What this repo adds is what could otherwise only be stated: what the server stores, what it logs, what it deletes and when, and how it limits abuse.

**Pre-v1.** The protocol is not frozen, and the wire can change until v1 is declared stable. What is still open is the open issues of this repo and of the client repo.

## What is here

| Path | Holds |
|---|---|
| `cmd/dromasd/` | The command: `dromasd serve`, and `dromasd account` and `dromasd limits` for the operator |
| `internal/server/` | The API (every route under `/v1/`, and `/to/<address>`, the page a box's link opens), the pass-through to a deployment's own site when it gives one (`-site-backend`), what each process holds in memory, the DynamoDB stream followers, the store (one memory over two backends: DynamoDB with S3 Express One Zone, or maps in the process) and the limits |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How this server is built: processes, memory, the pass check, request paths, storage, failure modes and the stages of scale |
| [`LIMITS.md`](LIMITS.md) | Every limit this server enforces, who pays for it, and where it is weak: there to be checked |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability privately, and what this server must get right beside the code and tests that hold it |
| `test/interop.sh` | The stock-tools client and the Go client, together, against a real `dromasd` |
| `test/working-key-openssh.sh` | A measurement, not a test: what stock `ssh-keygen` does with a certificate an identity signs for a working key (the client repo's issue #30) |
| `Dockerfile` | `dromasd`'s image: the static binary GoReleaser builds, copied onto distroless static (CA bundle, user `nonroot`, uid 65532); nothing is compiled in it. The echo box's image is the client repo's |
| `.github/workflows/docker-publish.yml` | The image from `main`, on every push, tagged `main`: GoReleaser's snapshot binaries into that `Dockerfile`, for `linux/amd64` and `linux/arm64`, published as `ghcr.io/dromas-dev/dromasd` with an attestation of the build and an attested SPDX SBOM (`gh attestation verify oci://ghcr.io/dromas-dev/dromasd@<digest> -R dromas-dev/dromas-server`). A release's image is `release.yml`'s |
| `Taskfile.yml`, `.github/workflows/release.yml`, `.goreleaser.yaml` | `dromasd`'s releases: `task release` signs the tag and pushes it, and the workflow checks it against `.github/allowed_signers`, runs CI on its commit, and publishes the image (GoReleaser's `dockers_v2`, the binary of the archives in it, with an attested SPDX SBOM) and archives for Linux on `amd64` and `arm64`, with an SBOM of each, every file attested, and `checksums.txt`, signed with cosign by the workflow; then it checks the release and the image as published and builds the release again to compare. The release's notes have the commands that check each |
| `bench/` | The measurements behind the microsecond figures |

A deployment's site (dromas.dev's front page and `llms.txt`) is not in this repo. `serve -site-backend <URL>` passes every request outside `/v1/` and `/to/` to the deployment's own web server, as a reverse proxy passes it, with `X-Forwarded-For` naming the client the limits see, and its answer back as that server sent it, a 404 among them; under `/v1/` and `/to/` every answer is the server's.

## Build and run

Each release is a static binary for Linux on `amd64` and `arm64` and an image, `ghcr.io/dromas-dev/dromasd:<version>`, both built from its signed tag by this repo's release workflow after its tests pass on that commit, the image holding the archive's very binary (`SECURITY.md`); `go install github.com/dromas-dev/dromas-server/cmd/dromasd@<version>` builds the same source. The major version is the protocol's, shared with the client: both are 0.x until the protocol is frozen, and the freeze is v1 of both.

From source, `go.mod` requires a release of the client module, which `go` fetches:

```sh
git clone https://github.com/dromas-dev/dromas-server
cd dromas-server
scripts/check.sh          # vet and the short tests; scripts/check.sh full is what CI runs
go run ./cmd/dromasd serve --dev
```

`serve --dev` is the whole server on the in-memory backend, with no AWS, listening on `127.0.0.1:8080`: nothing survives a restart. Point a client at it with `DROMAS_SERVER_URL=http://127.0.0.1:8080`.

`test/interop.sh` runs both clients, from the release `go.mod` requires, against a real `serve --dev`: mail both ways, renewal, revocation, certificates and the sender ACL. Its header says what it needs, and how to test post-quantum boxes when the packaged age is older than 1.3.

The other backend is three DynamoDB tables and an S3 Express One Zone directory bucket. `dromasd serve -h` lists every flag, and `ARCHITECTURE.md` § Storage has the layout. That mode also needs `-names`, the names clients call the server by: a box's pass is made for one server by name, and the server takes one only on a request that calls it by a name of its own (`ARCHITECTURE.md` § The pass check).

Run behind a reverse proxy that terminates TLS: `-listen` takes one or more TCP addresses (comma-separated, served alike), and `-trusted-proxy` names the proxy's addresses, whose `X-Forwarded-For` (its last entry) names the client every per-IP limit counts (`ARCHITECTURE.md` § Behind a reverse proxy). Without `-trusted-proxy` the peer is the client.

`-metrics-listen <address>` serves the operator's metrics at `/metrics` in Prometheus' text format, on a listener of its own: what they count is `ARCHITECTURE.md` § Metrics. Keep it off the internet: it is for the operator.

## Contributing

Every commit is signed off under the Developer Certificate of Origin: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0 (`LICENSE`), as is the client, [dromas-client](https://github.com/dromas-dev/dromas-client).
