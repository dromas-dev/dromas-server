#!/usr/bin/env bash
# scripts/check.sh: the checks a change must pass, one definition for a laptop
# and for CI (.github/workflows/ci.yml runs `full` and `vuln`; irongall-client's
# CI runs `full` here against its own commit).
#
#   scripts/check.sh         quick: gofmt, vet and the tests -short keeps, while working
#   scripts/check.sh full    CI's test job: gofmt, vet, every test, the skip check, test/interop.sh
#   scripts/check.sh push    full, then golangci-lint and govulncheck: before a push
#   scripts/check.sh vuln    govulncheck alone, at the version pinned here
#
# The tests build with -tags irongall_nofsync, so the client they drive flushes
# no write to the disk (irongall-client's client/fsync.go). -short skips the
# long tests, each of which says so; CI never passes it. On macOS,
# test/interop.sh needs bash 4 or later and GNU coreutils: Homebrew's go first
# in PATH when installed.
set -euo pipefail
cd "$(dirname "$0")/.."

govulncheck=golang.org/x/vuln/cmd/govulncheck@v1.9.0
tags=irongall_nofsync
darwin=
[ "$(uname -s)" = Darwin ] && darwin=1
if [ -n "$darwin" ] && command -v brew > /dev/null; then
  for d in "$(brew --prefix)/opt/coreutils/libexec/gnubin" "$(brew --prefix)/opt/bash/bin"; do
    if [ -d "$d" ]; then PATH="$d:$PATH"; fi
  done
fi
unset IRONGALL_HOME IRONGALL_BOX IG_HOME IG_BOX # no test may meet a real box

# On the in-memory store the AWS tests and the cost measurement skip; any
# other skip fails `full`.
allowed=(-e 'needs IRONGALL_TEST_BOXES_TABLE, IRONGALL_TEST_MSGS_TABLE' -e 'needs the AWS tables' -e 'set IRONGALL_COST=1 to measure')
if [ -n "$darwin" ]; then allowed+=(-e 'macOS loopback buffers'); fi

fail() { # an annotation on GitHub's page, a line on a terminal
  if [ -n "${GITHUB_ACTIONS-}" ]; then echo "::error::$*"; else echo "$*" >&2; fi
}

fmt() {
  local out
  out=$(gofmt -l .)
  if [ -n "$out" ]; then fail "not gofmt'd: $out"; return 1; fi
}

alltests() {
  local dir status
  dir=$(mktemp -d)
  set +e
  go test -tags "$tags" -count=1 -timeout 20m -json ./... | tee "$dir/test.json" | jq -rj --unbuffered 'select(.Action == "output") | .Output'
  status=${PIPESTATUS[0]}
  set -e
  jq -rs '[.[] | select(.Test != null)] | group_by([.Package, .Test])[] | select(any(.Action == "skip"))
    | "\(.[0].Package) \(.[0].Test): " + ([.[] | select(.Action == "output") | .Output
      | select(test("^ +[^ ]+\\.go:[0-9]+: ")) | sub("^ +"; "") | rtrimstr("\n")] | join(" "))' \
    "$dir/test.json" > "$dir/skips"
  echo "Skipped:"; cat "$dir/skips"
  if grep -v -F "${allowed[@]}" "$dir/skips"; then
    fail "the tests above skipped, and this machine has every tool they need"
    rm -rf "$dir"
    return 1
  fi
  rm -rf "$dir"
  return "$status"
}

full() {
  fmt
  go vet ./...
  alltests
  test/interop.sh
}

case ${1:-quick} in
  quick)
    fmt
    go vet ./...
    go test -tags "$tags" -short ./...
    ;;
  full) full ;;
  push)
    full
    golangci-lint run ./...
    go run "$govulncheck" ./...
    ;;
  vuln) go run "$govulncheck" ./... ;;
  *) sed -n '6,9p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
