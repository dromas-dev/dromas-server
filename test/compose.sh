#!/usr/bin/env bash
# compose.sh — examples/compose.yaml run as README.md's "Run it with Docker Compose" runs it, on this host, with DOMAIN=localhost,
# whose certificate Caddy makes from its own local authority, every image as the file pins it, and the Go client `dromas` from the
# dromas-client release this module requires (a go.work, if there is one, swaps in a checkout):
#   1. the stack starts from empty volumes: PostgreSQL, the migration, then dromas-server once healthy, then Caddy;
#   2. a message between two mailboxes through Caddy over TLS, its body under the data volume until it is received;
#   3. after docker compose down and up, the volumes kept, the same two mailboxes exchange another.
# Each mailbox is given its server and CA file at init, which writes them into its own config file, and the client's environment
# variables for them are unset: no call here reaches any other server system.
# Needs: docker with compose, go, jq, openssl, and ports 80 and 443 free. Run from anywhere: test/compose.sh
# The compose project is its own, dromas-compose-test, removed with its volumes however a run ends. The work dir is mktemp -d's, under
# $TMPDIR or /tmp; a run that passes deletes it, and one that fails names it and shows each service's log.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); repo=$(dirname "$here")
work=$(mktemp -d "${TMPDIR:-/tmp}/dromas-compose.XXXXXX") || { echo "no work dir"; exit 1; }
pass=0; fail=0
ok(){ echo "PASS $*"; pass=$((pass + 1)); }
bad(){ echo "FAIL $*"; fail=$((fail + 1)); }
compose(){ docker compose -p dromas-compose-test -f "$repo/examples/compose.yaml" --env-file "$work/.env" "$@"; }
trap 'rc=$?; [ "$rc" -eq 0 ] || { echo "work dir: $work"; compose logs --no-color --tail 40; }; compose down -v > /dev/null 2>&1 || { echo "docker compose down -v failed: the project dromas-compose-test is left"; rc=1; }; [ "$rc" -eq 0 ] && rm -rf "$work"; exit "$rc"' EXIT

export PATH=$PATH:/usr/local/go/bin
client=$(cd "$repo" && go mod download github.com/dromas-dev/dromas-client && go list -m -f '{{.Dir}}' github.com/dromas-dev/dromas-client) || { echo "no client module"; exit 1; }
(cd "$client" && go mod download && go build -o "$work/dromas" ./cmd/dromas) || { echo "build failed"; exit 1; }
box(){ n=$1; shift; env -u DROMAS_SERVER_URL -u DROMAS_CA_FILE HOME="$work/$n" XDG_CONFIG_HOME="$work/$n/config" XDG_DATA_HOME="$work/$n/data" XDG_STATE_HOME="$work/$n/state" "$work/dromas" "$@"; }

(umask 077; { echo DOMAIN=localhost; for v in POSTGRES_PASSWORD DROMAS_PASSWORD DROMAS_APP_PASSWORD; do echo "$v=$(openssl rand -hex 32)"; done; } > "$work/.env")

# Up, then each service as it should be, then Caddy's local root and a certificate served for localhost.
up(){
  compose up -d > "$work/up.log" 2>&1 || { bad "$1: docker compose up"; cat "$work/up.log"; return 1; }
  states=$(compose ps -a --format json | jq -s -r 'sort_by(.Service) | map("\(.Service) \(.State) \(.Health) \(.ExitCode)") | join(", ")')
  want="caddy running  0, dromas-migrate exited  0, dromas-server running healthy 0, postgres running healthy 0"
  [ "$states" = "$want" ] && ok "$1: every service as it should be" || { bad "$1: services: $states"; return 1; }
  for _ in $(seq 30); do compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$work/root.crt" > /dev/null 2>&1 && break; sleep 1; done
  for _ in $(seq 30); do curl -fsS --cacert "$work/root.crt" -o /dev/null https://localhost/v1/ 2> /dev/null && break; sleep 1; done
  curl -fsS --cacert "$work/root.crt" -o /dev/null https://localhost/v1/ && ok "$1: GET https://localhost/v1/ through Caddy" || { bad "$1: GET /v1/ through Caddy"; return 1; }
}

# One message from a to b, its body on the data volume once it is sent, and gone from it once b has it.
exchange(){
  text="$1, $(openssl rand -hex 8)"
  sent=$(printf '%s\n' "$text" | box a send "$B") && id=$(jq -er .id <<< "$sent") || { bad "$1: a sends: $sent"; return; }
  rm -rf "$work/bodies"; compose cp dromas-server:/home/nonroot/bodies "$work/bodies" > /dev/null 2>&1
  [ "$(find "$work/bodies" -type f 2> /dev/null | wc -l)" -eq 1 ] && ok "$1: its body under the data volume" || bad "$1: bodies: $(find "$work/bodies" -type f 2> /dev/null | wc -l)"
  got=$(box b recv --wait 30s)
  jq -e --arg id "$id" --arg body "$text"$'\n' 'select(.type == "message" and .id == $id and .envelope.body == $body)' <<< "$got" > /dev/null \
    && ok "$1: b has it, its body as sent" || bad "$1: b's recv: $got"
  rm -rf "$work/bodies"; compose cp dromas-server:/home/nonroot/bodies "$work/bodies" > /dev/null 2>&1
  [ "$(find "$work/bodies" -type f 2> /dev/null | wc -l)" -eq 0 ] && ok "$1: its body gone once received" || bad "$1: bodies left after the receipt"
}

if up "first start"; then
  for n in a b; do mkdir -p "$work/$n"; box $n init --server https://localhost --ca-file "$work/root.crt" > /dev/null || bad "$n: init"; done
  for n in a b; do [ "$(box $n config | jq -r '.values.server | "\(.value) \(.from)"')" = "https://localhost file" ] || bad "$n: its server is not its config file's https://localhost"; done
  A=$(box a addr | jq -r .address); B=$(box b addr | jq -r .address)
  box b peer allow "$A" > /dev/null || bad "b: peer allow a"
  exchange "first start"
  compose down > /dev/null 2>&1
  up "after a restart" && exchange "after a restart"
fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
