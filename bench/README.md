# bench/ — the measurements behind the microsecond figures

First run on 2026-10-10: 2× Neoverse-V2, Go 1.26.6, standard library only, a single core where noted. **They are evidence for design decisions, not a test suite.**

| Dir | Measures | How to run |
|---|---|---|
| `crypto/` | SSHSIG verify over 16 KiB (~71 µs; a forgery costs the same), SHA-256 / de-armor (~10–12 µs), SSH tag check (~0.08 µs), HMAC check of the owner token that was (~0.31 µs pooled), map lookup (~0.011 µs) | `cd bench/crypto && go test -bench . -benchtime 2s -count 3` |
| `crypto/base64_test.go` | **A TEST, not a benchmark:** Go's `encoding/base64` decodes 76-column-wrapped base64 (LF and CRLF) to the exact bytes, which `PROTOCOL.md` §11.10 relied on while a send carried its ciphertext as base64 inside JSON | `cd bench/crypto && go test -run TestWrappedBase64DecodesExactly -v .` |
| `poll/` | **A whole empty poll over loopback HTTP, against a real `dromasd serve --dev`: 33 to 34 µs of server CPU with a pass the server remembers** (2026-10-13; 40,000 polls, keep-alive, 0 errors, three runs). The same run on the server as it was with a 62-byte bearer token: 31 to 32 µs. `poll/srv`, a model of an earlier design with nothing but an HMAC check and a map lookup, measured ~19 µs on 2026-10-10 | below |

The memory and item-size measurements, and what a pass costs to check the first time and after, are `internal/server/cost_test.go` (`DROMAS_COST=1 go test ./internal/server -run TestCost -v`).

**Running `poll/` against the real server** (build into a scratch directory, here `$out`; `$box` is a new, empty directory for a box's state):

```sh
(cd bench/poll/cli && go build -o "$out/poll-cli" .)
go build -o "$out/dromasd" ./cmd/dromasd
go build -o "$out/dromas" github.com/dromas-dev/dromas-client/cmd/dromas
GOMAXPROCS=1 "$out/dromasd" serve --dev -listen 127.0.0.1:18777 -poll-burst 0 2> "$out/server.log" &
SP=$(pgrep -f "$out/dromasd serve")                      # the server's OWN pid, never $!
export DROMAS_HOME=$box DROMAS_BASE=http://127.0.0.1:18777
A=$("$out/dromas" init --no-pq); A=${A##*/}             # a box; init leaves its pass in $box/pass
U=$DROMAS_BASE/v1/$A/messages
GOMAXPROCS=1 "$out/poll-cli" 2000 "$U" "$(cat "$box/pass")"    # warm up
awk '{print $14+$15}' /proc/$SP/stat                      # CPU ticks before (1 tick = 10 ms)
GOMAXPROCS=1 "$out/poll-cli" 40000 "$U" "$(cat "$box/pass")"   # prints "requests 40000 bad 0"
awk '{print $14+$15}' /proc/$SP/stat                      # CPU ticks after → µs/poll = Δticks × 10000 / 40000
kill $SP
```

A pass lasts ten minutes, so the whole run fits in one. `poll-cli N` alone polls `poll/srv` (`go build` it and run it the same way), the model of 2026-10-10.

- **Five of these measure an earlier revision of the design, and are kept as the record of that measurement:** `crypto/tag_test.go` times a check of an `ssh-ed25519` recipient's tag, from when one SSH key both signed and received; `crypto/token_test.go` times the HMAC check of the owner token, which a pass the box signs replaced on 2026-10-13; `poll/srv` checks such a token and answers an empty list as `[]`, where the server now checks a pass and answers an object; and `crypto/base64_test.go` and the de-armor benchmark are from when a message's ciphertext travelled as base64 inside JSON, where it is now the body itself, raw, on a send and on a fetch.
- **SSHSIG is EMULATED** in `crypto/`: SHA-512 of the message plus an Ed25519 verify over the small signed blob, with no SSHSIG parser. A real parser adds negligible cost.
- **Stop the server by ITS pid, and run it by an absolute path.** Wrapped in `timeout` with an environment prefix, one `timeout` implementation failed to start it, and killing the wrapper orphaned the server. Started with an environment prefix and `&`, `$!` has named a process that was not the server: find the pid with `pgrep`.
- Never wrap a Go command in `ulimit -v`: the runtime reserves a large virtual arena and dies misleadingly.
- What stands in front of the server (a proxy, a tunnel, TLS termination) is not measured here, and costs more per poll than the server does.
