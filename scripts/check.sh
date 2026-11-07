#!/usr/bin/env bash
# scripts/check.sh: the checks a change must pass, one definition for a laptop
# and for CI (.github/workflows/ci.yml runs `full` and `vuln`; dromas-client's
# CI runs `full` here against its own commit, through a go.work).
#
#   scripts/check.sh         quick: gofmt, vet and the tests -short keeps, while working
#   scripts/check.sh full    CI's test job: gofmt, vet, every test (in memory, then on PostgreSQL), the skip check, test/interop.sh
#   scripts/check.sh push    full, then golangci-lint and govulncheck: before a push
#   scripts/check.sh vuln    govulncheck alone, at the version pinned here
#
# The tests build with -tags dromas_nofsync, so the client they drive flushes
# no write to the disk (dromas-client's client/fsync.go). -short skips the
# long tests, each of which says so; CI never passes it. On macOS,
# test/interop.sh needs bash 4 or later and GNU coreutils: Homebrew's go first
# in PATH when installed.
set -euo pipefail
cd "$(dirname "$0")/.."

govulncheck=golang.org/x/vuln/cmd/govulncheck@v1.9.0
tags=dromas_nofsync
darwin=
[ "$(uname -s)" = Darwin ] && darwin=1
if [ -n "$darwin" ] && command -v brew > /dev/null; then
  for d in "$(brew --prefix)/opt/coreutils/libexec/gnubin" "$(brew --prefix)/opt/bash/bin"; do
    if [ -d "$d" ]; then PATH="$d:$PATH"; fi
  done
fi
unset DROMAS_CONFIG DROMAS_PROFILE DR_HOME DR_MAILBOX # no test may meet a real mailbox

# `full` runs every test on the in-memory store, where the tests that need a
# shared store with a feed skip, then, with DROMAS_TEST_POSTGRES set (and
# libpq's environment naming a database kept for tests), every test again on
# PostgreSQL, where none may; any other skip fails it.
allowed=()
if [ -n "$darwin" ]; then allowed+=(-e 'macOS loopback buffers'); fi

fail() { # an annotation on GitHub's page, a line on a terminal
  if [ -n "${GITHUB_ACTIONS-}" ]; then echo "::error::$*"; else echo "$*" >&2; fi
}

fmt() {
  local out
  out=$(gofmt -l .)
  if [ -n "$out" ]; then fail "not gofmt'd: $out"; return 1; fi
}

alltests() { # [a skip's text to allow]...
  local dir status ok=("${allowed[@]}")
  for a in "$@"; do ok+=(-e "$a"); done
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
  if { [ ${#ok[@]} -eq 0 ] && grep . "$dir/skips"; } || { [ ${#ok[@]} -gt 0 ] && grep -v -F "${ok[@]}" "$dir/skips"; }; then
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
  DROMAS_TEST_POSTGRES='' alltests 'needs PostgreSQL'
  if [ -n "${DROMAS_TEST_POSTGRES-}" ]; then alltests; fi
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
