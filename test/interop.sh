#!/usr/bin/env bash
# interop.sh — the stock client, sh/dromas.sh from the dromas-client release this module requires (a go.work, if there is one, swaps in a checkout), with its real dr_api (curl),
# against a real `dromas-server serve --dev`, interoperating with the Go client `dromas` from the public client repo:
#   1. mail both ways between a recipe box and a Go box, sent to each box's link, across a prekey renewal on each side; the page each link opens;
#   2. the recipe's error path on a real problem+json body;
#   3. the envelope's optional fields from the Go client, and each client's sent/ record, with the real server's receipt;
#   4. a box whose identity is of the optional key type, in each client, and the sender key types a box declares;
#   5. a box whose clock is off from the server's;
#   6. revocation: a box revoked at the real server, by the Go client or with ssh-keygen and curl as PROTOCOL.md §10.1 shows, and each
#      client checking the proof it is shown; a record alone revokes;
#   7. certificates revoked: the Go client renews and revokes its earlier certificates, a revocation made with ssh-keygen alone, and each
#      client checking the one it is shown, refusing mail under a revoked certificate and following a box to its next one;
#   8. a revocation of an address with no box here: kept and served, its registration refused, and a Go box shown it before it
#      posts;
#   9. the sender ACL: a Go box's block reaches this server, which refuses the recipe box's send;
#  10. the pass's name: the server runs with --names, so every pass above was checked for the name it is called by, and one made
#      for another name is refused.
# The recipe runs a box of its own: the two clients meet over the wire, never in one box directory.
# Every script step runs in a FRESH shell (agents run each command in a new one). Every box is post-quantum: where the
# local age is older than 1.3, the client module's own (its go.mod's tool, built by go tool) goes first in PATH.
# Needs: go, bash ≥ 4, ssh-keygen, curl, jq, sha256sum, base64, od, GNU date (passof's date -d). Run from anywhere:
#   test/interop.sh            SCRIPT=<path> overrides the dromas.sh it sources.
# With DROMAS_TEST_BOXES_TABLE, DROMAS_TEST_MSGS_TABLE, DROMAS_TEST_ACCOUNTS_TABLE and DROMAS_TEST_BUCKET set, the server runs on those tables and
# that bucket instead of --dev: tables and a bucket kept for tests, never the ones a running server uses.
# The work dir is mktemp -d's, under $TMPDIR or /tmp, its own for each run. A run that passes deletes it, since it may be
# on tmpfs (memory) and it holds two builds; one that fails leaves it to look at, and names it.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); repo=$(dirname "$here")
work=$(mktemp -d "${TMPDIR:-/tmp}/dromas-interop.XXXXXX") || { echo "no work dir"; exit 1; }
pass=0; fail=0
ok(){ echo "PASS $*"; pass=$((pass + 1)); }
bad(){ echo "FAIL $*"; fail=$((fail + 1)); }
trap 'rc=$?; [ -n "${srv:-}" ] && kill "$srv" 2> /dev/null; [ "$rc" -eq 0 ] || { echo "work dir: $work"; [ -s "$work/server.log" ] && { echo "the server'"'"'s log, its end:"; tail -n 40 "$work/server.log"; }; }' EXIT   # a run that fails, however it ends, names its work dir and shows the server's log

export PATH=$PATH:/usr/local/go/bin
# The client is the module go.mod requires (go list -m answers with a go.work's checkout when there is one). Its commands are built in
# its own module, which lists what they import and the server's does not; the module cache is read-only, so go build only writes elsewhere.
client=$(cd "$repo" && go mod download github.com/dromas-dev/dromas-client && go list -m -f '{{.Dir}}' github.com/dromas-dev/dromas-client) || { echo "no client module"; exit 1; }
SCRIPT=${SCRIPT:-$client/sh/dromas.sh}
(cd "$repo" && go build -o "$work/dromas-server" ./cmd/dromas-server) && (cd "$client" && go mod download && go build -o "$work/dromas" ./cmd/dromas) || { echo "build failed"; exit 1; }
[ -r "$SCRIPT" ] || { echo "no $SCRIPT"; exit 1; }
echo "stock client: $SCRIPT ($(grep -c '^dr_[a-z_]*()' "$SCRIPT") functions)"

# The client module's modules, its tools' among them, came with its build
# above (go mod download), so go tool builds age here without a fetch.
age-keygen -pq > /dev/null 2>&1 || PATH=$(cd "$client" && dirname "$(go tool -n age)"):$(cd "$client" && dirname "$(go tool -n age-keygen)"):$PATH
age-keygen -pq > /dev/null 2>&1 || { echo "no age that makes post-quantum keys"; exit 1; }
echo "age: $(age --version)"
port=$((20000 + RANDOM % 12768))   # below Linux's ephemeral ports (32768 up: ip_local_port_range), which an outgoing connection may hold
if [ -n "${DROMAS_TEST_MSGS_TABLE:-}" ]; then
  store=(--boxes-table "$DROMAS_TEST_BOXES_TABLE" --msgs-table "$DROMAS_TEST_MSGS_TABLE" --accounts-table "$DROMAS_TEST_ACCOUNTS_TABLE" --bucket "$DROMAS_TEST_BUCKET" --names "127.0.0.1:$port")
else
  store=(--dev --names "127.0.0.1:$port")   # --dev takes a pass made for any name without --names: with it, every pass's name is checked (PROTOCOL.md §8)
fi
echo "server: dromas-server serve ${store[*]:0:6}"
"$work/dromas-server" serve "${store[@]}" --listen "127.0.0.1:$port" --poll-burst 0 --registrations-per-hour 0 2> "$work/server.log" & srv=$!   # every box here registers from one address
export DR_SERVER_URL="http://127.0.0.1:$port" DROMAS_SERVER_URL="http://127.0.0.1:$port"
for _ in $(seq 300); do   # up once the API answers other than 503 (loading)
  code=$(curl -s -o /dev/null -w '%{http_code}' "$DR_SERVER_URL/v1/$(printf '0%.0s' $(seq 64))"); [ "$code" != 000 ] && [ "$code" != 503 ] && break; sleep 0.1
done
[ "$code" != 000 ] && [ "$code" != 503 ] || { echo "the server did not answer on port $port"; exit 1; }

R="$work/r"; G="$work/g"
recipe(){ local home=$1; shift; DR_HOME=$home bash -c ". '$SCRIPT'; $*"; }   # a fresh shell per call
# The Go client holds mail from a sender its box has not allowed (PROTOCOL.md §12.3). These tests are of what the two clients
# send each other, so every box the Go client runs lands every sender's mail in inbox/, by its policy file, unless a test wrote one.
gocli(){ local home=$1; shift; mkdir -p -m 700 "$home" && { [ -e "$home/policy" ] || printf 'unknown inbox\n' > "$home/policy"; } && DROMAS_HOME=$home "$work/dromas" "$@"; }
holds(){ DROMAS_SERVER_URL=http://127.0.0.1:9 gocli "$1" revocation ask "$2" 2> /dev/null | jq -e '.type == "revoked"' > /dev/null; }   # <go box> <address>: it keeps a revocation of the address, with no server to ask (a box keeps its records in its state file)
through(){ gocli "$1" revocation ask "$2" 2> /dev/null | jq -r 'select(.type == "certificates_revoked") | .through'; }
passof(){ local a n t; a=$(cat "$1/address") && n=$(gocli "$1" status | jq -r .prekey_serial) && t=$(date -u -d "@$(( $(date +%s) + 600 ))" +%Y-%m-%dT%H:%M:%SZ) \
  && printf 'dromas-pass-v1\n%s\n%s\n%s\n' "$a" "${2:-${DR_SERVER_URL#http://}}" "$t" | ssh-keygen -q -Y sign -n "dromas-pass-v1:$a" -f "$1/work/$n-cert.pub" > "$work/pass.sig" \
  && printf 'dromas-pass address="%s", not_after="%s", signature="%s"' "$a" "$t" "$(base64 < "$work/pass.sig" | tr -d '\n')"; }   # <go box> → a pass its working key signs, as PROTOCOL.md §8 makes one with ssh-keygen   # <go box> <address> → the serial its revocation of certificates runs through, as the box holds it once it has asked
linkof(){ jq -er 'select(.type == "box") | .link'; }      # a box line, as init and addr print one → its link
revoked_line(){ printf '{"type":"revoked","address":"%s","message":"published to the server"}' "$1"; }      # <address> → the line revocation publish prints
record_of(){ local a; a=$(cat "$1/address") && printf 'dromas-revoke-v1\n%s\n' "$a" | ssh-keygen -q -Y sign -n "dromas-revoke-v1:$a" -f "$1/identity" > "$work/rev.sig" &&
  jq -cn --arg i "$(base64 < "$1/identity.doc" | tr -d '\n')" --arg s "$(base64 < "$work/rev.sig" | tr -d '\n')" '{type:"revocation_record", identity:$i, revocation_signature:$s}'; }      # <box dir> → its revocation record, made with ssh-keygen as PROTOCOL.md §10.3 shows: the recipe makes none
look(){ curl -s -o /dev/null -w '%{http_code}' "$DR_SERVER_URL/v1/$1"; }   # <address> → the status of a read of the box at this server: 410 once it is revoked

# --- 1. both ways, across renewals ---
dr_hex(){ [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
RL=$(recipe "$R" "dr_init" | linkof) && RA=${RL##*/} && dr_hex "$RA" && [ "$RL" = "$DR_SERVER_URL/to/$RA" ] && ok "recipe init prints its link: $RL" || bad "recipe init: $RL"
GL=$(gocli "$G" init | linkof) && GA=${GL##*/} && dr_hex "$GA" && [ "$GL" = "$DR_SERVER_URL/to/$GA" ] && ok "Go init prints its link: $GL" || bad "Go init: $GL"
for L in "$RL" "$GL"; do
  curl -sf "$L" | grep -qF "<code>${L##*/}</code>" && ok "the link opens its page: $L" || bad "no page at $L"
done
[ "$(curl -s -o /dev/null -w '%{http_code}' "$DR_SERVER_URL/to/$(tr a-f A-F <<< "$GA")")" = 404 ] && ok "a link in uppercase is 404, as clients refuse it" || bad "uppercase link page"

printf 'from Go, <b>&\n' | gocli "$G" send "$RL" > /dev/null && ok "Go → recipe: sent, to the recipe box's link" || bad "Go → recipe: send"
out=$(recipe "$R" dr_recv 2> "$work/err") && jq -e --arg f "$GA" '.envelope.body == "from Go, <b>&\n" and .envelope.from == $f' <<< "$out" > /dev/null \
  && ok "Go → recipe: delivered by dr_recv, verified" || bad "Go → recipe: dr_recv: $out $(cat "$work/err")"

printf 'from the recipe\n' > "$work/body"
recipe "$R" "dr_send $GL '$work/body'" && ok "recipe → Go: sent, to the Go box's link" || bad "recipe → Go: dr_send"
out=$(gocli "$G" recv 2> "$work/err") && jq -e --arg f "$RA" '.envelope.body == "from the recipe\n" and .envelope.from == $f' <<< "$out" > /dev/null \
  && ok "recipe → Go: delivered by dromas recv, verified" || bad "recipe → Go: recv: $out $(cat "$work/err")"

recipe "$R" "dr_rekey" && ok "recipe: dr_rekey" || bad "recipe: dr_rekey"
gocli "$G" prekey renew > /dev/null && ok "Go: prekey renew" || bad "Go: prekey renew"
printf 'after both renewals\n' | gocli "$G" send "$RA" > /dev/null && recipe "$R" "dr_send $GA '$work/body'" && ok "both ways after renewals: sent" || bad "send after renewals"
out=$(recipe "$R" dr_recv 2>&1) && grep -q 'after both renewals' <<< "$out" && ok "recipe receives after renewals" || bad "recipe after renewals: $out"
out=$(gocli "$G" recv 2>&1) && grep -q 'from the recipe' <<< "$out" && ok "Go receives after renewals" || bad "Go after renewals: $out"

# --- 2. the recipe's error path on a real problem+json ---
nobody=$(printf '%064d' 0)
err=$(recipe "$R" "dr_send $nobody '$work/body'" 2>&1); rc=$?
[ $rc -ne 0 ] && grep -qxF '{"type":"error","status":404,"code":"no_such_mailbox","message":"ERROR 404 no_such_mailbox"}' <<< "$err" && ! grep -q 'no box has this address' <<< "$err" && ok "recipe prints a real problem's status and code, and none of the server's words (PROTOCOL.md §11.3)" || bad "recipe error path: rc=$rc $err"

# --- 3. the Go client's optional fields, and each client's sent/ record ---
gocli "$G" alias add sh "$RL" > /dev/null || bad "Go alias add"
M1=11111111-2222-4333-8444-555555555555
id=$(printf 'threaded, from Go\n' | gocli "$G" send --subject 'a subject' --reply-to $M1 sh | jq -r 'select(.type == "sent") | .id') && dr_hex "$id" || bad "Go send with flags, to an alias: $id"
out=$(recipe "$R" dr_recv 2> "$work/err") && jq -e --arg m $M1 '.envelope.subject == "a subject" and .envelope.in_reply_to == $m and .envelope.body == "threaded, from Go\n"' <<< "$out" > /dev/null \
  && ok "Go → recipe: subject and in_reply_to arrive" || bad "Go → recipe with flags: $out $(cat "$work/err")"
mid=$(jq -r .envelope.msg_id <<< "$out")
jq -e --arg id "$id" --argjson d "$out" '.receipt.id == $id and (.receipt | keys == ["expires_at", "id", "received_at"]) and keys == ["envelope", "receipt"] and .envelope == $d.envelope' "$G/sent/$RA.$mid.json" > /dev/null \
  && ok "Go's sent/ record is the envelope its recipient delivered, and the real server's receipt" || bad "Go's sent/ record: $(cat "$G/sent/$RA.$mid.json" 2>&1)"
recipe "$R" "dr_send $GA '$work/body'" || bad "recipe send"
out=$(gocli "$G" recv 2> "$work/err") && jq -e --arg f "$RA" '.envelope.from == $f and .envelope.body == "from the recipe\n"' <<< "$out" > /dev/null \
  && ok "recipe → Go: delivered" || bad "recipe → Go: $out $(cat "$work/err")"
rec="$R/sent/$GA.$(jq -r .envelope.msg_id <<< "$out").json"
jq -e --argjson d "$out" '(.receipt | keys == ["expires_at", "id", "received_at"]) and keys == ["envelope", "receipt"] and .envelope == $d.envelope' "$rec" > /dev/null && [ -e "$G/inbox/$(jq -r .receipt.id "$rec").json" ] \
  && ok "the recipe's sent/ record is the same, its receipt naming the file in the recipient's inbox/" || bad "the recipe's sent/ record: $(cat "$rec" 2>&1)"

# --- 4. a box whose identity is of the optional key type, ecdsa-sha2-nistp256, in each client ---
# The recipe takes the identity key it finds, so its box's key is made with ssh-keygen first. Each client's P-256 box
# then exchanges mail with the other client's Ed25519 box of step 1, which declared that it verifies the type.
RP="$work/rp"; GP="$work/gp"; mkdir -p "$RP"
ssh-keygen -q -t ecdsa -b 256 -N '' -C '' -f "$RP/identity" < /dev/null
RPL=$(recipe "$RP" "dr_init" | linkof) && RPA=${RPL##*/} && dr_hex "$RPA" && [ "$(sed -n 2p "$RP/identity.doc" | cut -d' ' -f1)" = ecdsa-sha2-nistp256 ] \
  && ok "recipe init on a P-256 identity made by ssh-keygen" || bad "recipe init on P-256: $RPL"
GPO=$(gocli "$GP" init --identity-type ecdsa-sha2-nistp256 2> "$work/err") && GPL=$(linkof <<< "$GPO") && GPA=${GPL##*/} && dr_hex "$GPA" && jq -e '.message | startswith("WARNING: ")' <<< "$GPO" > /dev/null \
  && ok "Go init --identity-type ecdsa-sha2-nistp256, with its warning" || bad "Go init on P-256: $GPL $(cat "$work/err")"
[ "$(curl -s "$DR_SERVER_URL/v1/$GA" | jq -c .sender_key_types)" = '["ssh-ed25519","ecdsa-sha2-nistp256"]' ] && [ "$(curl -s "$DR_SERVER_URL/v1/$RA" | jq -c .sender_key_types)" = '["ssh-ed25519","ecdsa-sha2-nistp256"]' ] \
  && ok "each client's box is served with the sender key types it declared" || bad "sender_key_types: $(curl -s "$DR_SERVER_URL/v1/$GA" | jq -c .sender_key_types) $(curl -s "$DR_SERVER_URL/v1/$RA" | jq -c .sender_key_types)"
printf 'p256 recipe to go\n' > "$work/body5"
recipe "$RP" "dr_send $GL '$work/body5'" && out=$(gocli "$G" recv 2> "$work/err") && jq -e --arg f "$RPA" '.envelope.body == "p256 recipe to go\n" and .envelope.from == $f' <<< "$out" > /dev/null \
  && ok "recipe on P-256 → Go: delivered, verified under a certificate ssh-keygen made with a P-256 key" || bad "recipe on P-256 → Go: $out $(cat "$work/err")"
printf 'go to p256 recipe\n' | gocli "$G" send "$RPL" > /dev/null && out=$(recipe "$RP" dr_recv 2> "$work/err") && jq -e --arg f "$GA" '.envelope.body == "go to p256 recipe\n" and .envelope.from == $f' <<< "$out" > /dev/null \
  && ok "Go → recipe on P-256: delivered" || bad "Go → recipe on P-256: $out $(cat "$work/err")"
printf 'p256 go to recipe\n' | gocli "$GP" send "$RL" > /dev/null && out=$(recipe "$R" dr_recv 2> "$work/err") && jq -e --arg f "$GPA" '.envelope.body == "p256 go to recipe\n" and .envelope.from == $f' <<< "$out" > /dev/null \
  && ok "Go on P-256 → recipe: delivered, verified by ssh-keygen under a certificate the Go client made with a P-256 key" || bad "Go on P-256 → recipe: $out $(cat "$work/err")"
printf 'recipe to p256 go\n' > "$work/body5"
recipe "$R" "dr_send $GPL '$work/body5'" && out=$(gocli "$GP" recv 2> "$work/err") && jq -e --arg f "$RA" '.envelope.body == "recipe to p256 go\n" and .envelope.from == $f' <<< "$out" > /dev/null \
  && ok "recipe → Go on P-256: delivered" || bad "recipe → Go on P-256: $out $(cat "$work/err")"
# A box that declares Ed25519 only: the server refuses it a P-256 sender's mail, and the Go client does not even post it.
GE="$work/ge"
GEL=$(DROMAS_SENDER_KEY_TYPES=ssh-ed25519 gocli "$GE" init | linkof) && GEA=${GEL##*/} && [ "$(curl -s "$DR_SERVER_URL/v1/$GEA" | jq -c .sender_key_types)" = '["ssh-ed25519"]' ] \
  && ok "a box told to declare Ed25519 only is served so" || bad "DROMAS_SENDER_KEY_TYPES: $(curl -s "$DR_SERVER_URL/v1/$GEA")"
out=$(printf 'x\n' | gocli "$GP" send "$GEL" 2>&1); [ $? -ne 0 ] && grep -q "does not verify identities of this box's key type" <<< "$out" \
  && ok "Go on P-256 does not send to a box that does not verify its key type" || bad "Go on P-256 → Ed25519-only box: $out"
out=$(recipe "$RP" "dr_send $GEL '$work/body5'" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 403 sender_key_type" <<< "$out" \
  && ok "the server refuses the recipe's P-256 box the same send: 403 sender_key_type, and no receipt" || bad "recipe on P-256 → Ed25519-only box: $out"

# --- 5. a box whose clock is off from the server's (PROTOCOL.md §15.7) ---
# The recipe reads one clock, dr_now, which is set apart here; the server and the Go boxes keep the real one. Each Go
# box is made at that moment, so no certificate is newer than the one its mail is signed under.
clock(){ echo "dr_now(){ echo \$((\$(date -u +%s) + ($1))); }"; }   # <seconds> → the recipe's clock, that far from the real one
for c in "-540 9 minutes slow" "2940 49 minutes fast"; do
  off=${c%% *}; name=${c#* }; d="$work/clock$off"; gf="$work/gf$off"
  L=$(recipe "$d" "$(clock "$off"); dr_init" 2> "$work/err" | linkof) && A=${L##*/} && dr_hex "$A" && GFL=$(gocli "$gf" init | linkof) && GFA=${GFL##*/} \
    && printf 'to the box whose clock is off\n' | gocli "$gf" send "$L" > /dev/null \
    && out=$(recipe "$d" "$(clock "$off"); dr_recv" 2>> "$work/err") && jq -e --arg f "$GFA" '.envelope.body == "to the box whose clock is off\n" and .envelope.from == $f' <<< "$out" > /dev/null \
    && printf 'from the box whose clock is off\n' > "$work/body6" && recipe "$d" "$(clock "$off"); dr_send $GFL '$work/body6'" 2>> "$work/err" \
    && out=$(gocli "$gf" recv 2>> "$work/err") && jq -e --arg f "$A" '.envelope.body == "from the box whose clock is off\n" and .envelope.from == $f' <<< "$out" > /dev/null \
    && recipe "$d" "$(clock "$off"); dr_rekey" 2>> "$work/err" \
    && ok "a recipe box whose clock is $name registers, renews, and exchanges mail with a Go box made that moment" || bad "clock $name: $out $(cat "$work/err")"
done
out=$(recipe "$work/clock-late" "$(clock -660); dr_init" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 401 pass_expired" <<< "$out" && grep -q "the server dates its answer 20" <<< "$out" && grep -q "this machine's clock reads" <<< "$out" \
  && ok "a recipe box 11 minutes slow is refused at its pass: the server's answer is dated by its clock, and the recipe says that beside what its own reads" || bad "clock 11 minutes slow: $out"
out=$(recipe "$work/clock-early" "$(clock 3660); dr_init" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 400 prekey_time" <<< "$out" && grep -q "the server dates its answer 20" <<< "$out" \
  && L=$(recipe "$work/clock-early" "dr_init" 2> "$work/err" | linkof) && dr_hex "${L##*/}" \
  && ok "a recipe box first made 61 minutes fast is refused, the answer dated by the server's clock; with the clock right, the same box registers" || bad "clock 61 minutes fast: $out $(cat "$work/err")"

# --- 6. revocation (PROTOCOL.md §10.1): the server keeps the identity's own signature and shows it in the read of the box, and each client checks it ---
V1="$work/v1"; V2="$work/v2"; V3="$work/v3"; V4="$work/v4"; V5="$work/v5"
V1L=$(recipe "$V1" "dr_init" | linkof) && V1A=${V1L##*/} && V2L=$(gocli "$V2" init | linkof) && V2A=${V2L##*/} && V3L=$(gocli "$V3" init | linkof) && V3A=${V3L##*/} \
  && V4L=$(recipe "$V4" "dr_init" | linkof) && V4A=${V4L##*/} && V5L=$(gocli "$V5" init | linkof) && V5A=${V5L##*/} || bad "revocation: the boxes"
[ "$(curl -s -D "$work/head" -o "$work/box.json" -w '%{http_code}' "$DR_SERVER_URL/v1/$V1A")" = 200 ] && jq -e '(has("revoked_certificates") or has("revoked_certificates_signature")) | not' "$work/box.json" > /dev/null \
  && [ "$(tr -d '\r' < "$work/head" | grep -i '^cache-control:' | cut -d' ' -f2)" = no-store ] \
  && ok "a box nobody revoked: read 200 with no revocation in it, and the API's answers say no-store" || bad "not revoked: $(curl -s -D - "$DR_SERVER_URL/v1/$V1A")"
# A recipe box's record, made with ssh-keygen and published with curl as PROTOCOL.md §10.3 shows; mail it had sent a Go box is refused there,
# by the proof the server shows.
printf 'sent before the revocation\n' > "$work/body7"; recipe "$V1" "dr_send $V2L '$work/body7'" 2> "$work/err" || bad "revocation: the recipe's send: $(cat "$work/err")"
printf 'waiting in the box that is revoked\n' | gocli "$V2" send "$V1L" > /dev/null 2> "$work/err" || bad "revocation: the Go send: $(cat "$work/err")"
record_of "$V1" > "$work/v1.json" && [ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' --data-binary "@$work/v1.json" "$DR_SERVER_URL/v1/$V1A/revocations")" = 201 ] && [ "$(look "$V1A")" = 410 ] \
  && curl -s "$DR_SERVER_URL/v1/$V1A" | jq -e '.code == "revoked" and (.record | keys == ["identity","revocation_signature","type"] and .type == "revocation_record")' > /dev/null \
  && ok "a recipe box's record, made with ssh-keygen and put with curl: 410 from then on, and the server shows the record in it to anyone" || bad "the recipe box's revocation: $(cat "$work/v1.json")"
out=$(gocli "$V2" recv 2>&1); [ $? -eq 0 ] && grep -q '"code":"revoked"' <<< "$out" && ! grep -q '"body"' <<< "$out" && holds "$V2" "$V1A" \
  && ok "the Go client refuses mail from the revoked recipe box, and keeps the revocation it checked" || bad "Go recv from a revoked box: $out"
out=$(printf 'x\n' | gocli "$V2" send "$V1L" 2>&1); [ $? -ne 0 ] && grep -q "REVOKED: $V1A" <<< "$out" && ls "$V2"/outbox/failed/*.P > /dev/null 2>&1 \
  && ok "the Go client sends nothing to it: REVOKED, and the message moves to outbox/failed/" || bad "Go send to a revoked box: $out"
out=$(recipe "$V1" "dr_recv" 2>&1); [ $? -ne 0 ] && grep -q "REVOKED: this box's own address" <<< "$out" && ok "the revoked recipe box is told so by its own revocation" || bad "revoked recipe box's recv: $out"
# The Go client revokes its box; the recipe refuses the mail it had sent, and sends it nothing.
printf 'sent before the revocation\n' | gocli "$V3" send "$V4L" > /dev/null 2> "$work/err" || bad "revocation: the Go send: $(cat "$work/err")"
out=$(gocli "$V3" revocation publish "$V4A" 2>&1); [ $? -ne 0 ] && [ "$(look "$V3A")" = 200 ] \
  && ok "the Go client does not revoke for another box's address" || bad "Go revoke with another address: $out"
out=$(gocli "$V3" revocation publish "$V3A" 2>&1) && [ "$out" = "$(revoked_line $V3A)" ] && [ "$(look "$V3A")" = 410 ] \
  && jq -e '.revoked == true' <<< "$(gocli "$V3" status 2> /dev/null)" > /dev/null \
  && ok "the Go client revokes its box, and its status says so" || bad "Go revoke: $out"
out=$(recipe "$V4" "dr_recv" 2>&1); [ $? -eq 0 ] && grep -q '"code":"revoked"' <<< "$out" && ! grep -q '"body"' <<< "$out" && [ -s "$V4/peers/$V3A/revoke.sig" ] \
  && ok "the recipe refuses mail from the box the Go client revoked, and keeps the revocation it checked" || bad "recipe recv from a revoked box: $out"
out=$(recipe "$V4" "dr_send $V3L '$work/body7'" 2>&1); [ $? -ne 0 ] && grep -q "REVOKED" <<< "$out" && ok "the recipe sends nothing to it: REVOKED" || bad "recipe send to a revoked box: $out"
# A record made in advance revokes with no box and no key, by either client or by curl; what is not one is refused.
gocli "$V5" revocation make > "$work/v5.json" 2> /dev/null && [ "$(look "$V5A")" = 200 ] && ok "a record is made, and nothing is published" || bad "Go revocation"
jq -c --arg s "$(printf 'revoke it' | base64)" '.revocation_signature = $s' "$work/v5.json" > "$work/v5-junk.json"
[ "$(curl -s -X PUT -H 'Content-Type: application/json' --data-binary "@$work/v5-junk.json" "$DR_SERVER_URL/v1/$V5A/revocations" | jq -r .code)" = bad_revocation ] \
  && [ "$(curl -s -X PUT -H 'Content-Type: application/json' --data-binary "@$work/v5.json" "$DR_SERVER_URL/v1/$V4A/revocations" | jq -r .code)" = identity_mismatch ] \
  && [ "$(look "$V5A")" = 200 ] \
  && ok "the server refuses what is not a revocation of that address: 400 bad_revocation, 400 identity_mismatch" || bad "junk revocations"
out=$(DROMAS_HOME="$work/nobox" "$work/dromas" revocation publish --record "$work/v5.json" "$V5A" 2>&1) && [ "$out" = "$(revoked_line $V5A)" ] && [ "$(look "$V5A")" = 410 ] \
  && [ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' --data-binary "@$work/v5.json" "$DR_SERVER_URL/v1/$V5A/revocations")" = 410 ] \
  && ok "the Go client's record revokes from the Go client with no box, and the same record again is 410: nothing changes" || bad "revoke with a record: $out"

# --- 7. certificates revoked (PROTOCOL.md §10.2): the identity's revocation ends what a certificate signed, and the address goes on ---
W1="$work/w1"; W2="$work/w2"; W3="$work/w3"
W1L=$(gocli "$W1" init | linkof) && W1A=${W1L##*/} && W2L=$(recipe "$W2" "dr_init" | linkof) && W2A=${W2L##*/} && W3L=$(gocli "$W3" init | linkof) && W3A=${W3L##*/} || bad "revoked certificates: the boxes"
kept(){ jq -r .revoked_certificates "$1" | base64 -d; }   # <the record a box keeps a revocation of certificates as> → the statement in it
put(){ curl -s -o "$work/put.json" -w '%{http_code}' -X PUT -H 'Content-Type: application/json' --data-binary "@$1" "$DR_SERVER_URL/v1/$2/revocations"; }   # <record> <address> → the status; the body is left in put.json
printf 'under the first certificate\n' > "$work/body8"
gocli "$W1" send "$W2L" < "$work/body8" > /dev/null 2> "$work/err" && gocli "$W1" send "$W3L" < "$work/body8" > /dev/null 2>> "$work/err" && recipe "$W2" "dr_send $W3L '$work/body8'" 2>> "$work/err" || bad "revoked certificates: the first sends: $(cat "$work/err")"
# The Go client renews and revokes every certificate before its new one. Each client is shown the revocation, checks it, and refuses what the old one signed.
out=$(gocli "$W1" cert revoke-earlier 2>&1) && [ "$(curl -s -o "$work/box.json" -w '%{http_code}' "$DR_SERVER_URL/v1/$W1A")" = 200 ] \
  && jq -e 'has("revoked_certificates") and has("revoked_certificates_signature") and has("prekey")' "$work/box.json" > /dev/null \
  && ok "the Go client renews and revokes its earlier certificates: the server shows the revocation to anyone in the read of the box, and the address goes on" || bad "cert revoke-earlier: $out"
printf 'under the second certificate\n' > "$work/body8b"
gocli "$W1" send "$W2L" < "$work/body8b" > /dev/null 2> "$work/err" && gocli "$W1" send "$W3L" < "$work/body8b" > /dev/null 2>> "$work/err" || bad "revoked certificates: the sends after the renewal: $(cat "$work/err")"
out=$(recipe "$W2" "dr_recv" 2>&1); [ $? -eq 0 ] && [ "$(grep -c '"code":"certificate_revoked"' <<< "$out")" = 1 ] && grep -q 'under the second certificate' <<< "$out" && ! grep -q 'under the first certificate' <<< "$out" \
  && curl -sf "$DR_SERVER_URL/v1/$W1A" | jq -r .revoked_certificates | base64 -d | cmp -s - <(kept "$W2/peers/$W1A/revoked-certs.json") && [ ! -e "$W2/peers/$W1A/revoke.sig" ] \
  && ok "the recipe refuses mail under the certificate the Go box revoked, delivers mail under its new one, and keeps the revocation it checked" || bad "recipe recv after the revocation: $out"
out=$(gocli "$W3" recv 2>&1); [ $? -eq 0 ] && [ "$(grep -c '"code":"certificate_revoked"' <<< "$out")" = 1 ] && grep -q 'under the second certificate' <<< "$out" && [ "$(grep -c 'under the first certificate' <<< "$out")" = 1 ] \
  && [ "$(through "$W3" "$W1A")" = "$(kept "$W2/peers/$W1A/revoked-certs.json" | sed -n 3p)" ] \
  && ok "the Go client does the same, and takes the recipe box's mail under a certificate nobody revoked" || bad "Go recv after the revocation: $out"
recipe "$W2" "dr_send $W1L '$work/body8'" 2> "$work/err" && gocli "$W3" send "$W1L" < "$work/body8" > /dev/null 2>> "$work/err" && out=$(gocli "$W1" recv 2>&1) && [ "$(grep -c '"body"' <<< "$out")" = 2 ] \
  && w1=$(gocli "$W1" status | jq -r .prekey_serial) && [ "$(cat "$W2/peers/$W1A/serial" "$W2/peers/$W1A/cert-serial" | tr '\n' ' ')" = "$w1 $w1 " ] \
  && ok "both clients write to the box at its second certificate, naming its prekey by both serials" || bad "sends to the renewed box: $(cat "$work/err") $out"
# A revocation of certificates made with ssh-keygen alone: the recipe makes none, and its box's identity signs like any other.
mkcerts(){ printf 'dromas-revoke-certs-v1\n%s\n%s\n' "$W2A" "$2" > "$work/$1.certs" && ssh-keygen -q -Y sign -n "dromas-revoke-certs-v1:$W2A" -f "$3" < "$work/$1.certs" > "$work/$1.sig" \
  && jq -cn --arg i "$(base64 < "$W2/identity.doc" | tr -d '\n')" --arg l "$(base64 < "$work/$1.certs" | tr -d '\n')" --arg g "$(base64 < "$work/$1.sig" | tr -d '\n')" '{identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$work/$1.json"; }   # <name> <serial> <key>
w2a=$(cat "$W2/serial")   # a box takes each number from its clock: the recipe box's first, and after its renewal its second
recipe "$W2" "dr_send $W3L '$work/body8'" 2> "$work/err" && recipe "$W2" "dr_rekey" 2>> "$work/err" && recipe "$W2" "dr_send $W3L '$work/body8b'" 2>> "$work/err" || bad "revoked certificates: the recipe's renewal: $(cat "$work/err")"
w2b=$(cat "$W2/serial"); [ "$w2b" -gt "$w2a" ] || bad "revoked certificates: the recipe's renewal took no later number: $w2a, then $w2b"
mkcerts bywork "$w2a" "$W2/work/$w2b-cert.pub" && mkcerts one "$w2a" "$W2/identity" && mkcerts lower $((w2a - 1)) "$W2/identity" && mkcerts two "$w2b" "$W2/identity" || bad "revoked certificates: ssh-keygen did not sign a revocation"
[ "$(put "$work/bywork.json" "$W2A")" = 400 ] && [ "$(jq -r .code "$work/put.json")" = bad_revocation ] && [ "$(put "$work/one.json" "$W3A")" = 400 ] && [ "$(jq -r .code "$work/put.json")" = identity_mismatch ] \
  && curl -sf "$DR_SERVER_URL/v1/$W2A" | jq -e '(has("revoked_certificates") or has("revoked_certificates_signature")) | not' > /dev/null \
  && ok "the server refuses a revocation of certificates the box's working key signed, and one sent for another address: 400 bad_revocation, 400 identity_mismatch" || bad "junk revocations: $(cat "$work/put.json")"
[ "$(put "$work/one.json" "$W2A")" = 200 ] && [ "$(put "$work/one.json" "$W2A")" = 200 ] && [ "$(put "$work/lower.json" "$W2A")" = 409 ] && [ "$(jq -r .code "$work/put.json")" = conflict ] \
  && curl -sf "$DR_SERVER_URL/v1/$W2A" | jq -r .revoked_certificates | base64 -d | cmp -s - "$work/one.certs" \
  && ok "a revocation of certificates signed with ssh-keygen alone is taken with no pass: 200, the same again 200, one through a lower serial 409 conflict" || bad "the recipe box's revocation: $(cat "$work/put.json")"
out=$(gocli "$W3" recv 2>&1); [ $? -eq 0 ] && [ "$(grep -c '"code":"certificate_revoked"' <<< "$out")" = 1 ] && grep -q 'under the second certificate' <<< "$out" && ! grep -q 'under the first certificate' <<< "$out" \
  && [ "$(through "$W3" "$W2A")" = "$w2a" ] \
  && ok "the Go client refuses the recipe box's mail under the certificate that revocation covers, and delivers its mail under the next" || bad "Go recv after the recipe box's revocation: $out"
# A revocation through the box's CURRENT certificate: the server takes no pass of the box and no mail for it, until it renews.
[ "$(put "$work/two.json" "$W2A")" = 200 ] || bad "the second revocation: $(cat "$work/put.json")"
out=$(recipe "$W2" "dr_recv" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 401 certificate_revoked" <<< "$out" && ok "a box whose current certificate is revoked has no pass the server takes" || bad "a revoked certificate's recv: $out"
# A sender asks what the server holds about a box before it posts to it (PROTOCOL.md §12.2): shown the revocation, it refuses the box's statement itself.
out=$(gocli "$W3" send "$W2L" < "$work/body8" 2>&1); [ $? -ne 0 ] && grep -q "under a certificate its identity has revoked" <<< "$out" && ! grep -q "prekey_expired" <<< "$out" && ls "$W3"/outbox/*.P > /dev/null 2>&1 \
  && [ "$(through "$W3" "$W2A")" = "$w2b" ] && ! ls "$W3"/outbox/*.json > /dev/null 2>&1 \
  && ok "a sender asks before it posts: shown the revocation, it keeps it, seals nothing to a statement under a revoked certificate, and the message waits in the outbox" || bad "a send to a box whose certificate is revoked: $out"
recipe "$W2" "dr_rekey" 2> "$work/err" && gocli "$W3" outbox flush > /dev/null 2>> "$work/err" && out=$(recipe "$W2" "dr_recv" 2>&1) && grep -q 'under the first certificate' <<< "$out" \
  && ok "one renewal, under a new certificate, cures both: the box polls again, and the waiting message is delivered" || bad "after the box renewed: $(cat "$work/err") $out"
out=$(gocli "$W3" revocation ask "$W2L" 2> /dev/null) && [ "$out" = "{\"type\":\"certificates_revoked\",\"address\":\"$W2A\",\"through\":$w2b}" ] && out=$(gocli "$W1" revocation ask "$W3L" 2> "$work/err") && [ "$(jq -r '"\(.type) \(.address)"' <<< "$out")" = "not_revoked $W3A" ] && jq -e '.message | contains("the server'"'"'s word")' <<< "$out" > /dev/null \
  && ok "asked at any time, the server shows a box's revocation of its certificates, or that it holds nothing, which the client says as the server's word" || bad "revoked --ask: $out $(cat "$work/err")"

# --- 8. a revocation of an address with no box here (PROTOCOL.md §11.15): every server keeps and serves one, for any address ---
at(){ curl -s -o /dev/null -w '%{http_code}' "$DR_SERVER_URL/v1/$1/revocations"; }   # <address> → the status of the read of its revocations here
X1="$work/x1"; X3="$work/x3"; X6="$work/x6"
X1L=$(gocli "$X1" init | linkof) && X1A=${X1L##*/} && X6L=$(gocli "$X6" init | linkof) && X6A=${X6L##*/} || bad "the boxes of section 8"
mkdir -p -m 700 "$X3" && ssh-keygen -q -t ed25519 -N '' -C '' -f "$X3/identity" && gocli "$X3" revocation make > "$work/x3.json" 2> "$work/err" && X3A=$(jq -r .identity "$work/x3.json" | base64 -d | sha256sum | cut -c1-64) && X3L="$DR_SERVER_URL/to/$X3A" \
  || bad "a record of an address never registered: $(cat "$work/err")"
[ "$(at "$X1A")" = 404 ] && [ "$(curl -s "$DR_SERVER_URL/v1/$X1A/revocations" | jq -r .code)" = not_revoked ] && [ "$(at "$X3A")" = 404 ] \
  && ok "the server answers 404 not_revoked for an address it holds no revocation of, with a box there or none" || bad "the read of revocations, before anything"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' --data-binary "@$work/x3.json" "$DR_SERVER_URL/v1/$X3A/revocations")" = 201 ] \
  && [ "$(look "$X3A")" = 410 ] && cmp -s <(curl -s "$DR_SERVER_URL/v1/$X3A" | jq -S .record) <(jq -S . "$work/x3.json") && cmp -s <(curl -s "$DR_SERVER_URL/v1/$X3A/revocations" | jq -S .) <(jq -S . "$work/x3.json") \
  && ok "a server with no box at an address keeps a revocation of it, and serves the record, in the read of the address (410) and in the read of its revocations" || bad "a revocation of an address with no box"
out=$(gocli "$X3" init 2>&1); [ $? -ne 0 ] && grep -qi 'revoked' <<< "$out" && [ "$(look "$X3A")" = 410 ] \
  && ok "and refuses that address's registration: it is revoked here, box or none" || bad "a registration of an address revoked with no box: $out"
printf 'to an address its owner ended\n' > "$work/body9"
out=$(gocli "$X6" send "$X3L" < "$work/body9" 2>&1); [ $? -ne 0 ] && grep -q "REVOKED: $X3A is revoked" <<< "$out" && holds "$X6" "$X3A" && ls "$X6"/outbox/failed/"$X3A".*.P > /dev/null 2>&1 \
  && ok "a Go box is shown that revocation by the read before its post: it is checked and kept, and nothing is posted" || bad "a send to the revoked address: $out"
out=$(gocli "$X6" cert revoke-earlier 2>&1) && [ "$(curl -s "$DR_SERVER_URL/v1/$X6A/revocations" | jq -r 'keys | join(",")')" = "identity,revoked_certificates,revoked_certificates_signature,type" ] \
  && cmp -s <(curl -s "$DR_SERVER_URL/v1/$X6A/revocations" | jq -r .revoked_certificates) <(curl -s "$DR_SERVER_URL/v1/$X6A" | jq -r .revoked_certificates) \
  && ok "cert revoke-earlier publishes the revocation of certificates, which both reads serve alike" || bad "a revocation of certificates: $out"
out=$(gocli "$X6" revocation publish "$X6A" 2>&1) && [ "$out" = "$(revoked_line $X6A)" ] && out=$(gocli "$X6" revocation publish "$X6A" 2>&1) && [ "$out" = "$(revoked_line $X6A)" ] \
  && curl -s "$DR_SERVER_URL/v1/$X6A/revocations" | jq -e '.revocation_signature and .revoked_certificates' > /dev/null \
  && ok "the same publish again is answered 410 by a server that holds the address revoked, which the client takes once the record it serves verifies" || bad "revoke again: $out"

# --- 9. the sender ACL: a Go box that blocks a recipe box, and a recipe send that the server then refuses ---
XB="$work/xb"; XBL=$(recipe "$XB" "dr_init" | linkof) && XBA=${XBL##*/} || bad "recipe init for the ACL: $XBL"
out=$(gocli "$G" peer block "$XBL" 2>&1) && curl -s -H "Authorization: $(passof "$G")" "$DR_SERVER_URL/v1/$GA/acl" | jq -e --arg x "$XBA" 'keys == ["allow","deny"] and .allow == ["*"] and .deny == [$x]' > /dev/null \
  && out=$(recipe "$XB" "dr_send $GL '$work/body'" 2>&1); [ $? -ne 0 ] && grep -q 'ERROR 403 sender_not_allowed' <<< "$out" && grep -q 'nothing is sent' <<< "$out" && [ ! -e "$XB/outbox" ] \
  && ok "a Go box's block reaches the server as its ACL, which refuses the recipe box's send: nothing is sent or kept" || bad "the ACL: $out"

# --- 10. the pass's name: a pass made for a name this server is not called by is refused (PROTOCOL.md §8) ---
other="127.0.0.2:$port"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $other" -H "Authorization: $(passof "$G" "$other")" "$DR_SERVER_URL/v1/$GA/acl")" = 401 ] \
  && [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: $(passof "$G")" "$DR_SERVER_URL/v1/$GA/acl")" = 200 ] \
  && ok "a pass made for a name the server is not called by is refused, and one made for the name it is called by is taken" || bad "the pass's name check"

echo "interop: $pass PASS, $fail FAIL"
[ "$fail" -eq 0 ] || exit 1
rm -rf -- "${work:?}"
