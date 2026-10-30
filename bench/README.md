# bench/ — the measurements behind the microsecond figures

Measured 2026-10-10 unless dated otherwise: 2× Neoverse-V2, Go 1.26.6, standard library only, a single core where noted. **They are evidence for design decisions, not a test suite.**

| Dir | Measures | How to run |
|---|---|---|
| `crypto/` | SSHSIG verify over 16 KiB (~71 µs; a forgery costs the same), SHA-256 / de-armor (~10–12 µs), SSH tag check (~0.08 µs), HMAC check of an owner token (~0.31 µs pooled), map lookup (~0.011 µs) | `cd bench/crypto && go test -bench . -benchtime 2s -count 3` |
| `crypto/base64_test.go` | **A TEST, not a benchmark:** Go's `encoding/base64` decodes 76-column-wrapped base64 (LF and CRLF) to the exact bytes | `cd bench/crypto && go test -run TestWrappedBase64DecodesExactly -v .` |
| `poll/` | **A whole empty poll over loopback HTTP, against a real `dromas-server serve --dev`: 33 to 34 µs of server CPU with a pass the server remembers** (measured 2026-10-13; 40,000 polls, keep-alive, 0 errors, three runs). The same run with a 62-byte bearer token in place of the pass: 31 to 32 µs. `poll/srv`, a model with nothing but an HMAC check and a map lookup: ~19 µs (measured 2026-10-10) | below |

The memory and item-size measurements, and what a pass costs to check the first time and after, are `internal/server/cost_test.go` (`DROMAS_COST=1 go test ./internal/server -run TestCost -v`).

**Running `poll/` against the real server** (build into a scratch directory, here `$out`; `$mailbox` is a new, empty directory for a mailbox's state):

```sh
(cd bench/poll/cli && go build -o "$out/poll-cli" .)
go build -o "$out/dromas-server" ./cmd/dromas-server
go build -o "$out/dromas" github.com/dromas-dev/dromas-client/cmd/dromas
GOMAXPROCS=1 "$out/dromas-server" serve --dev --listen 127.0.0.1:18777 --poll-burst 0 2> "$out/server.log" &
SP=$(pgrep -f "$out/dromas-server serve")                      # the server's OWN pid, never $!
export DROMAS_HOME=$mailbox DROMAS_SERVER_URL=http://127.0.0.1:18777
A=$("$out/dromas" init --no-pq); A=${A##*/}             # a mailbox; init leaves its pass in $mailbox/pass
U=$DROMAS_SERVER_URL/v1/$A/messages
GOMAXPROCS=1 "$out/poll-cli" 2000 "$U" "$(cat "$mailbox/pass")"    # warm up
awk '{print $14+$15}' /proc/$SP/stat                      # CPU ticks before (1 tick = 10 ms)
GOMAXPROCS=1 "$out/poll-cli" 40000 "$U" "$(cat "$mailbox/pass")"   # prints "requests 40000 bad 0"
awk '{print $14+$15}' /proc/$SP/stat                      # CPU ticks after → µs/poll = Δticks × 10000 / 40000
kill $SP
```

A pass lasts ten minutes, so the whole run fits in one. `poll-cli N` alone polls `poll/srv` (`go build` it and run it the same way), the model above.

- **Five of these measure designs the server does not use, kept as measurements:** `crypto/tag_test.go` times a check of an `ssh-ed25519` recipient's tag, for one SSH key that both signs and receives; `crypto/token_test.go` times the HMAC check of an owner token, where the server checks a pass the mailbox signs; `poll/srv` checks such a token and answers an empty list as `[]`, where the server checks a pass and answers an object; and `crypto/base64_test.go` and the de-armor benchmark are for a ciphertext carried as base64 inside JSON, where a send and a fetch carry it as the body itself, raw.
- **SSHSIG is EMULATED** in `crypto/`: SHA-512 of the message plus an Ed25519 verify over the small signed blob, with no SSHSIG parser. A real parser adds negligible cost.
- **Stop the server by ITS pid, and run it by an absolute path.** Wrapped in `timeout` with an environment prefix, one `timeout` implementation fails to start it, and killing the wrapper orphans the server. Started with an environment prefix and `&`, `$!` can name a process that is not the server: find the pid with `pgrep`.
- Never wrap a Go command in `ulimit -v`: the runtime reserves a large virtual arena and dies misleadingly.
- What stands in front of the server (a proxy, a tunnel, TLS termination) is not measured here, and costs more per poll than the server does.
