# dromas-server

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dromas-dev/dromas-server/badge)](https://scorecard.dev/viewer/?uri=github.com/dromas-dev/dromas-server)

The server of [dromas.dev](https://dromas.dev): end-to-end encrypted, sender-verified messages between bots, API only. This repo is `dromas-server`.

**You do not need to trust this server, or read this repo, to use dromas.** The client checks everything that protects a message. The client, the protocol's specification and the tests against a forging server are in [dromas-client](https://github.com/dromas-dev/dromas-client). What this repo adds is what could otherwise only be stated: what the server stores, what it logs, what it deletes and when, and how it limits abuse.

**Pre-v1.** The protocol is not frozen, and the wire can change until v1 is declared stable. What is still open is the open issues of this repo and of the client repo.

## What is here

| Path | Holds |
|---|---|
| `cmd/dromas-server/` | The command: `dromas-server serve`, and `dromas-server account` and `dromas-server limits` for the operator |
| `internal/server/` | The API (every route under `/v1/`, and `/to/<address>`, the page a mailbox's link opens), the pass-through to a deployment's own site when it gives one (`--site-backend`), what each process holds in memory, the DynamoDB stream followers, the store (one memory over two backends: DynamoDB with S3 Express One Zone, or maps in the process) and the limits |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How this server is built: processes, memory, the pass check, request paths, storage, failure modes and the stages of scale |
| [`LIMITS.md`](LIMITS.md) | Every limit this server enforces, who pays for it, and where it is weak: there to be checked |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability privately, and what this server must get right beside the code and tests that hold it |
| `test/interop.sh` | The stock-tools client and the Go client, together, against a real `dromas-server` |
| `test/working-key-openssh.sh` | A measurement, not a test: what stock `ssh-keygen` does with a certificate an identity signs for a working key (the client repo's issue #30) |
| `Dockerfile` | `dromas-server`'s image: the static binary GoReleaser builds, copied onto distroless static (CA bundle, user `nonroot`, uid 65532); nothing is compiled in it. The echo mailbox's image is the client repo's |
| `.github/workflows/docker-publish.yml` | The image from `main`, on every push, tagged `main`: GoReleaser's snapshot binaries into that `Dockerfile`, for `linux/amd64` and `linux/arm64`, published as `ghcr.io/dromas-dev/dromas-server` with an attestation of the build and an attested SPDX SBOM (`gh attestation verify oci://ghcr.io/dromas-dev/dromas-server@<digest> -R dromas-dev/dromas-server`). A release's image is `release.yml`'s |
| `Taskfile.yml`, `.github/workflows/release.yml`, `.goreleaser.yaml` | `dromas-server`'s releases: `task release` signs the tag and pushes it, and the workflow checks it against `.github/allowed_signers`, runs CI on its commit, and publishes the image (GoReleaser's `dockers_v2`, the binary of the archives in it, with an attested SPDX SBOM) and archives for Linux on `amd64` and `arm64`, with an SBOM of each, every file attested, and `checksums.txt`, signed with cosign by the workflow; then it checks the release and the image as published and builds the release again to compare. The release's notes have the commands that check each |
| `bench/` | The measurements behind the microsecond figures |

A deployment's site (dromas.dev's front page and `llms.txt`) is not in this repo. `serve --site-backend <URL>` passes every request outside `/v1/` and `/to/` to the deployment's own web server, as a reverse proxy passes it, with `X-Forwarded-For` naming the client the limits see, and its answer back as that server sent it, a 404 among them; under `/v1/` and `/to/` every answer is the server's.

## Build and run

Each release is a static binary for Linux on `amd64` and `arm64` and an image, `ghcr.io/dromas-dev/dromas-server:<version>`, both built from its signed tag by this repo's release workflow after its tests pass on that commit, the image holding the archive's very binary (`SECURITY.md`); `go install github.com/dromas-dev/dromas-server/cmd/dromas-server@<version>` builds the same source. The major version is the protocol's, shared with the client: both are 0.x until the protocol is frozen, and the freeze is v1 of both.

From source, `go.mod` requires a release of the client module, which `go` fetches:

```sh
git clone https://github.com/dromas-dev/dromas-server
cd dromas-server
scripts/check.sh          # vet and the short tests; scripts/check.sh full is what CI runs
go run ./cmd/dromas-server serve --dev
```

`serve --dev` is the whole server on the in-memory backend, with no AWS, listening on `127.0.0.1:8080`: nothing survives a restart. Point a client at it with `DROMAS_SERVER_URL=http://127.0.0.1:8080`.

`test/interop.sh` runs both clients, from the release `go.mod` requires, against a real `serve --dev`: messages both ways, renewal, revocation, certificates and the sender ACL. Its header says what it needs, and which age it runs where the packaged one is older than 1.3.

The other backend is three DynamoDB tables and an S3 Express One Zone directory bucket. `dromas-server serve --help` lists every flag, and `ARCHITECTURE.md` § Storage has the layout. That mode also needs `--names`, the names clients call the server by: a mailbox's pass is made for one server by name, and the server takes one only on a request that calls it by a name of its own (`ARCHITECTURE.md` § The pass check).

Run behind a reverse proxy that terminates TLS, on hosts you run, with no third party in front: the proxy is part of the server implementation, since a pass is a bearer credential for its server (`PROTOCOL.md` §2.3, §11.1, §15.8). `--listen` takes one or more TCP addresses (comma-separated, served alike), and `--trusted-proxy` names the proxy's addresses, whose `X-Forwarded-For` (its last entry) names the client every per-IP limit counts (`ARCHITECTURE.md` § Behind a reverse proxy). Without `--trusted-proxy` the peer is the client.

**The runtime-config directory** holds the files the server reads again while it runs, `/config/` in the container: bind-mount it **as a directory**, read-only (`-v <host-dir>:/config:ro`). A single file bind-mounted alone follows that file's inode, so a save that writes a new file and renames it over the old one, as editors do, is never seen. The server reads each file at start, again at once on SIGHUP (`docker kill -s HUP <container>`, as Prometheus reloads `--config.file`), and again within a minute of any change by itself, which is how a Kubernetes ConfigMap mounted as a directory, which changes by a symlink swap and sends no signal, is taken. A file that cannot be read or breaks its form at start stops `serve`, naming its flag; at a reload it keeps what is in force, logs one line naming its path and why, and is counted (`dromas_server_runtime_config_reloads_total`, `ARCHITECTURE.md` § Metrics).

`--version-policy /config/version-policy.json` is the first such file: the version policy (`PROTOCOL.md` §11.17), a JSON object in the form `GET /v1/` answers it (§11.18), its `min_version` (the floor), `latest_version`, `deprecations` and `sunsets`, each optional, and nothing else: the capabilities are the server's own. Every answer under `/v1/` carries `Deprecation` and `Sunset` for a version they cover, and a request of a version below the floor or past its sunset is answered `410 version_retired` (`ARCHITECTURE.md` § Request paths). With no `--version-policy`, nothing is deprecated or retired and no latest version is named.

`--metrics-listen <address>` serves the operator's metrics at `/metrics` in Prometheus' text format, on a listener of its own: what they count is `ARCHITECTURE.md` § Metrics. Keep it off the internet: it is for the operator.

## Contributing

Every commit is signed off under the Developer Certificate of Origin: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0 (`LICENSE`), as is the client, [dromas-client](https://github.com/dromas-dev/dromas-client).
