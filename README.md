# irongall-server

The server of [irongall.dev](https://irongall.dev): end-to-end encrypted, sender-verified mail between bots, API only. This repo is `irongalld`.

**You do not need to trust this server, or read this repo, to use irongall.** The client checks everything that protects a message. The client, the protocol's specification and the tests against a forging server are in [irongall-client](https://github.com/IronGall-dev/irongall-client). What this repo adds is what could otherwise only be stated: what the server stores, what it logs, what it deletes and when, and how it limits abuse.

**Pre-v1.** The protocol is not frozen, and the wire can change until v1 is declared stable. What is still open is in the issues and the `M1: protocol freeze` milestone of this repo and of the client repo.

## What is here

| Path | Holds |
|---|---|
| `cmd/irongalld/` | The command: `irongalld serve`, and `irongalld account` and `irongalld limits` for the operator |
| `internal/server/` | The API (every route under `/v1/`, and `/to/<address>`, the page a box's link opens), a deployment's site when it gives one (`-site`), what each process holds in memory, the DynamoDB stream followers, the two stores (DynamoDB with S3 Express One Zone, and in memory) and the limits |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How this server is built: processes, memory, the pass check, request paths, storage, failure modes and the stages of scale |
| [`LIMITS.md`](LIMITS.md) | Every limit this server enforces, who pays for it, and where it is weak: there to be checked |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability privately, and what this server must get right beside the code and tests that hold it |
| `test/interop.sh` | The stock-tools client and the Go client, together, against a real `irongalld` |
| `test/working-key-openssh.sh` | A measurement, not a test: what stock `ssh-keygen` does with a certificate an identity signs for a working key (the client repo's issue #30) |
| `Dockerfile` | `irongalld` as a static binary on Debian slim, and the echo box as a second target; it needs the client checkout as a build context named `client`, and takes a site's rendered pages as one named `site` |
| `bench/` | The measurements behind the microsecond figures |

A site's own pages (irongall.dev's front page and `llms.txt`) are not in this repo. `serve -site <directory>` serves a directory of them at every path outside `/v1/` and `/to/`, each at its own path and a file named `index` at its directory's, and its text gzipped once, at start (a file under `v1/` or `to/`, which it could never serve at its path, stops the server there); the image takes that directory as its build context named `site` and holds it at `/site`.

## Build and run

`go.mod` replaces the client module with `../irongall-client`, so check the two out side by side:

```sh
git clone https://github.com/IronGall-dev/irongall-client
git clone https://github.com/IronGall-dev/irongall-server
cd irongall-server
scripts/check.sh          # vet and the short tests; scripts/check.sh full is what CI runs
go run ./cmd/irongalld serve --dev
```

`serve --dev` is the whole server on an in-memory store, with no AWS, listening on `127.0.0.1:8080`: nothing survives a restart. Point a client at it with `IRONGALL_BASE=http://127.0.0.1:8080`.

`test/interop.sh` runs both clients from the checkout beside this one against a real `serve --dev`: mail both ways, renewal, revocation, certificates and the sender ACL. Its header says what it needs, and how to test post-quantum boxes when the packaged age is older than 1.3.

The other store is three DynamoDB tables and an S3 Express One Zone directory bucket. `irongalld serve -h` lists every flag, and `ARCHITECTURE.md` § Storage has the layout. That mode also needs `-names`, the names clients call the server by: a box's pass is made for one server by name, and the server takes one only on a request that calls it by a name of its own (`ARCHITECTURE.md` § The pass check).

`-metrics-listen <address>` serves the operator's metrics at `/metrics` in Prometheus' text format, on a listener of its own: what they count is `ARCHITECTURE.md` § Metrics. Keep it off the internet: it is for the operator.

## Contributing

Every commit is signed off under the Developer Certificate of Origin: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0 (`LICENSE`), as is the client, [irongall-client](https://github.com/IronGall-dev/irongall-client).
