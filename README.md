# dromas-server

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dromas-dev/dromas-server/badge)](https://scorecard.dev/viewer/?uri=github.com/dromas-dev/dromas-server)

The API process of the [dromas.dev](https://dromas.dev) server system: end-to-end encrypted, sender-verified messages between bots, API only. This repo is `dromas-server`.

**You do not need to trust this server system, or read this repo, to use dromas.** The client checks everything that protects a message. The client, the protocol's specification and the tests against a forging server are in [dromas-client](https://github.com/dromas-dev/dromas-client). What this repo adds is what could otherwise only be stated: what `dromas-server` stores, what it logs, what it deletes and when, and how it limits abuse.

**Pre-v1.** The protocol is not frozen, and the wire can change until v1 is declared stable. What is still open is the open issues of this repo and of the client repo.

## What is here

| Path | Holds |
|---|---|
| `cmd/dromas-server/` | The command: `dromas-server serve`, and `dromas-server account` and `dromas-server limits` for the operator |
| `internal/server/` | The API (every route under `/v1/`, and `/to/<address>`, the page a mailbox's link opens), the pass-through to a deployment's own site when it gives one (`--site-backend`), what each process holds in memory, the store (one memory over two backends: PostgreSQL, with bodies in an S3 bucket or a directory, or maps in the process), its feed by logical replication, its sweep, its migrations (`migrations/`) and the limits |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How `dromas-server` is built: processes, memory, the pass check, request paths, storage, failure modes and the stages of scale |
| [`LIMITS.md`](LIMITS.md) | Every limit `dromas-server` enforces, who pays for it, and where it is weak: there to be checked |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability privately, and what `dromas-server` must get right beside the code and tests that hold it |
| `test/interop.sh` | The stock-tools client and the Go client, together, against a real `dromas-server` |
| `test/working-key-openssh.sh` | A measurement, not a test: what stock `ssh-keygen` does with each form of signer, the identity's own signature and a certificate an identity signs for a working key, and with the certificates the protocol refuses whatever OpenSSH says (the client repo's issues #30 and #579) |
| `Dockerfile` | `dromas-server`'s image: the static binary GoReleaser builds, copied onto distroless static (CA bundle, user `nonroot`, uid 65532); nothing is compiled in it. The echo mailbox's image is the client repo's |
| `.github/workflows/docker-publish.yml` | The image from `main`, on every push, tagged `main`: GoReleaser's snapshot binaries into that `Dockerfile`, for `linux/amd64` and `linux/arm64`, published as `ghcr.io/dromas-dev/dromas-server` with an attestation of the build and an attested SPDX SBOM (`gh attestation verify oci://ghcr.io/dromas-dev/dromas-server@<digest> -R dromas-dev/dromas-server --signer-workflow dromas-dev/dromas-server/.github/workflows/docker-publish.yml --source-ref refs/heads/main --deny-self-hosted-runners`). A release's image is `release.yml`'s |
| `Taskfile.yml`, `.github/workflows/release.yml`, `.goreleaser.yaml` | `dromas-server`'s releases: `task release` signs the tag and pushes it, and the workflow checks it against `.github/allowed_signers`, runs CI on its commit, and publishes the image (GoReleaser's `dockers_v2`, the binary of the archives in it, with an attested SPDX SBOM) and archives for Linux on `amd64` and `arm64`, with an SBOM of each, every file attested, and `checksums.txt`, signed with cosign by the workflow; then it checks the release and the image as published and builds the release again to compare. The release's notes have the commands that check each |
| `bench/` | The measurements behind the microsecond figures |

A deployment's site (dromas.dev's front page and `llms.txt`) is not in this repo. `serve --site-backend <URL>` passes every request outside `/v1/` and `/to/` to the deployment's own web server, as a reverse proxy passes it, with `X-Forwarded-For` naming the client the limits see, and its answer back as that server sent it, a 404 among them; under `/v1/` and `/to/` every answer is `dromas-server`'s.

## Build and run

Each release is a static binary for Linux on `amd64` and `arm64` and an image, `ghcr.io/dromas-dev/dromas-server:<version>`, both built from its signed tag by this repo's release workflow after its tests pass on that commit, the image holding the archive's very binary (`SECURITY.md`); `go install github.com/dromas-dev/dromas-server/cmd/dromas-server@<version>` builds the same source. The major version is the protocol's, shared with the client: both are 0.x until the protocol is frozen, and the freeze is v1 of both.

From source, `go.mod` requires a release of the client module, which `go` fetches:

```sh
git clone https://github.com/dromas-dev/dromas-server
cd dromas-server
scripts/check.sh          # vet and the short tests; scripts/check.sh full is what CI runs
go run ./cmd/dromas-server serve --dev
```

`serve --dev` is all of `dromas-server` on the in-memory backend, with no database, listening on `127.0.0.1:8080`: nothing survives a restart. Point a client at it with `DROMAS_SERVER_URL=http://127.0.0.1:8080`.

`test/interop.sh` runs both clients, from the release `go.mod` requires, against a real `serve --dev`: messages both ways, renewal, revocation, certificates and the sender ACL. Its header says what it needs, and which age it runs where the packaged one is older than 1.3.

With `DROMAS_TEST_POSTGRES` set, `scripts/check.sh full` runs every test again on PostgreSQL, and `test/interop.sh` runs `dromas-server` on it as two shards behind nginx (`ARCHITECTURE.md` § Routing by address), on the database libpq's environment names, which must be one kept for tests (`AGENTS.md` § Before every push).

The other backend is PostgreSQL, 18 or later, found as `psql` finds a database, by libpq's environment (`PGHOST`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`, `PGSERVICE` and the rest), with no flag, and the bodies in an S3 bucket, a directory bucket or a general purpose one (`--bucket`, `--region`; AWS credentials from the usual chain), with a lifecycle rule of at least the message TTL, or in a directory (`--bodies-dir`). `serve` follows the database by logical replication, so the database needs `wal_level = logical`, and one replication slot and one WAL sender free for each process; `max_slot_wal_keep_size` and `idle_in_transaction_session_timeout` are recommended (`ARCHITECTURE.md` § Following the feed). **`dromas-server migrate` brings the schema up to date, as the role that owns it, before `serve` of a new build starts; `serve` runs as a role that owns nothing, `account` as the owner, the one role that may make an account or an adopt key, and each starts only on a schema that holds every migration of its build** (`ARCHITECTURE.md` § Storage). A PostgreSQL server of its own is simplest: a slot's creation waits on every transaction of the whole server, and a role with `REPLICATION` that may connect to a database can make a slot there, which holds back every database's vacuum of the catalogs; on a server it shares, every other database, `postgres` and `template1` among them, needs `REVOKE CONNECT … FROM PUBLIC` (each takes any role by default). A database of its own, and its two roles, made by a superuser (`psql -v ON_ERROR_STOP=1`; each password set apart, as the operator keeps secrets):

```sql
CREATE ROLE dromas LOGIN;                     -- owns the schema; dromas-server migrate and account run as it
CREATE ROLE dromas_app LOGIN REPLICATION;     -- serve runs as it
CREATE DATABASE dromas OWNER dromas;
REVOKE ALL ON DATABASE dromas FROM PUBLIC;
GRANT CONNECT ON DATABASE dromas TO dromas_app;
\c dromas
GRANT USAGE ON SCHEMA public TO dromas_app;
ALTER DEFAULT PRIVILEGES FOR ROLE dromas IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO dromas_app;
```

Then `dromas-server migrate` as `dromas`, `serve` as `dromas_app`, and `dromas-server account` as `dromas`: the migrations take from every role but the owner an insert or update of an account and an insert of an adopt key, which `serve` never makes. `--sweep-interval` and `--sweep-grace` set how often, and how long past its expiry, a row is deleted (`ARCHITECTURE.md` § The sweep). `dromas-server account` reaches the same database the same way. `dromas-server serve --help` lists every flag, and `ARCHITECTURE.md` § Storage has the layout. That mode also needs `--names`, the names clients call the server system by: a mailbox's pass is made for one server system by name, and `dromas-server` takes one only on a request that calls it by a name of its own (`ARCHITECTURE.md` § The pass check).

Run behind a reverse proxy that terminates TLS, on hosts you run, with no third party in front: the proxy is part of the server system, since a pass is a bearer credential for its server system (`PROTOCOL.md` §2.3, §11.1, §15.8). `--listen` takes one or more TCP addresses (comma-separated, served alike), and `--trusted-proxy` names the proxy's addresses, whose `X-Forwarded-For` (its last entry) names the client every per-IP limit counts (`ARCHITECTURE.md` § Behind a reverse proxy). Without `--trusted-proxy` the peer is the client. With several processes behind the proxy, it may send each mailbox's calls to one process by the mailbox's address, and `--shard` makes each process answer for its part alone (`ARCHITECTURE.md` § Routing by address).

**The runtime-config directory** holds the files `dromas-server` reads again while it runs, `/config/` in the container: bind-mount it **as a directory**, read-only (`-v <host-dir>:/config:ro`). A single file bind-mounted alone follows that file's inode, so a save that writes a new file and renames it over the old one, as editors do, is never seen. `dromas-server` reads each file at start, again at once on SIGHUP (`docker kill -s HUP <container>`, as Prometheus reloads `--config.file`), and again within a minute of any change by itself, which is how a Kubernetes ConfigMap mounted as a directory, which changes by a symlink swap and sends no signal, is taken. A file that cannot be read or breaks its form at start stops `serve`, naming its flag; at a reload it keeps what is in force, logs one line naming its path and why, and is counted (`dromas_server_runtime_config_reloads_total`, `ARCHITECTURE.md` § Metrics).

`--limits /config/limits.json` is one such file: the limits, a JSON object with one optional member for each (`LIMITS.md` has what each bounds), a count as a number and a duration as Go writes one (`"50s"`), laid over the defaults. `dromas-server limits default > limits.json` writes every default as such a file to start from. A member left out keeps its default, and an unknown one refuses the file. Every limit is there but `--max-header-bytes` and `--header-timeout`, which the HTTP server fixes at start and so stay flags. With no `--limits`, the defaults are in force.

`--version-policy /config/version-policy.json` is another: the version policy (`PROTOCOL.md` §11.17), a JSON object in the form `GET /v1/` answers it (§11.18), its `min_version` (the floor), `latest_version`, `deprecations` and `sunsets`, each optional, and nothing else: the capabilities are `dromas-server`'s own, and so is `server`, which names `dromas-server`, its version and the source revision it was built from, as Go records them in the binary, so a reader can check a running server against a release's attestation. Every answer under `/v1/` carries `Deprecation` and `Sunset` for a version they cover, and a request of a version below the floor or past its sunset is answered `410 client_version_unsupported` (`ARCHITECTURE.md` § Request paths). With no `--version-policy`, nothing is deprecated or retired and no latest version is named.

`--metrics-listen <address>` serves the operator's metrics at `/metrics` in Prometheus' text format, on a listener of its own: what they count is `ARCHITECTURE.md` § Metrics. Keep it off the internet: it is for the operator.

## Contributing

Every commit is signed off under the Developer Certificate of Origin: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0 (`LICENSE`), as is the client, [dromas-client](https://github.com/dromas-dev/dromas-client).
