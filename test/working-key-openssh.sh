#!/bin/sh
# working-key-openssh.sh — what stock ssh-keygen does with the two forms of signer (PROTOCOL.md §5): the identity's own signature,
# and a certificate the identity signs for a working key; and with the two certificates the
# protocol refuses whatever OpenSSH says, one of the identity's own key and one valid "forever" (dromas-client issues #30 and #579,
# where the results are). A measurement, not a test of our code: nothing of ours is run.
#   test/working-key-openssh.sh make  <dir>   make keys, certificates and signatures in <dir> (which must not exist)
#   test/working-key-openssh.sh check <dir>   verify what is in <dir>, whichever OpenSSH made it
# Each row is a verdict: "ok" it is the expected one, "!!!" it is not, neither when the row is a reading with no expectation.
# On another OpenSSH (8.1p1 is alpine:3.11), with <dir>'s parent mounted so each version can check what the other made:
#   docker run --rm -v "$PWD/test:/t:ro" -v <parent>:/d alpine:3.11 sh -c \
#     'apk add --no-cache openssh-client openssh-keygen >/dev/null; sh /t/working-key-openssh.sh make /d/c; sh /t/working-key-openssh.sh check /d/c'
# Needs ssh, ssh-keygen and, only if signing with -f work-cert.pub fails, ssh-agent and ssh-add. POSIX sh: it runs in BusyMailbox.
set -u
mode=$1; d=$2
A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
C=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
ns="dromas-msg-v1:$B"
echo "== $mode $d on $(ssh -V 2>&1)"

mk() { # name ca principal validity serial [extra ssh-keygen -s options]
  name=$1; ca=$2; prin=$3; val=$4; ser=$5; shift 5
  mkdir -p "$name"; cp work "$name/work"; cp work.pub "$name/work.pub"; chmod 600 "$name/work"
  if ssh-keygen -q -s "$ca" -I work -n "$prin" -V "$val" -z "$ser" "$@" "$name/work.pub" 2>"$name/cert.err"
  then echo "cert $name: made"
  else echo "cert $name: FAILED: $(head -1 "$name/cert.err" | cut -c1-120)"; fi
}

sgn() { # name
  name=$1
  if ssh-keygen -Y sign -n "$ns" -f "$name/work-cert.pub" < m > "$name/m.sig" 2>"$name/sign.err"
  then echo "sign $name: with -f work-cert.pub"; echo file > "$name/route"; return; fi
  : > "$name/m.sig"
  echo "sign $name: -f work-cert.pub FAILED: $(head -1 "$name/sign.err" | cut -c1-120)"
  eval "$(ssh-agent -s)" >/dev/null
  ssh-add -q "$name/work" 2>"$name/add.err"
  if ssh-keygen -Y sign -n "$ns" -f "$name/work-cert.pub" < m > "$name/m.sig" 2>"$name/sign.err2"
  then echo "sign $name: through ssh-agent holding the certificate"; echo agent > "$name/route"
  else : > "$name/m.sig"; echo "sign $name: the agent route FAILED too: $(head -1 "$name/sign.err2" | cut -c1-120)"; fi
  ssh-agent -k >/dev/null 2>&1
}

vfy() { # label expect signers principal namespace sig msg [extra -Y verify options]
  label=$1; exp=$2; signers=$3; prin=$4; n=$5; sig=$6; msg=$7; shift 7
  if [ ! -s "$sig" ]; then echo "  SKIP     | $label (no signature was made)"; return; fi
  out=$(ssh-keygen -Y verify -f "$signers" -I "$prin" -n "$n" -s "$sig" "$@" < "$msg" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then got=Good; else got=refused; fi
  if [ "$exp" = "?" ]; then flag="    "; elif [ "$got" = "$exp" ]; then flag="ok  "; else flag="!!! "; fi
  printf '  %s%-7s | %s | %s\n' "$flag" "$got" "$label" "$(echo "$out" | head -1 | cut -c1-100)"
}

if [ "$mode" = make ]; then
  if [ -e "$d" ]; then echo "$d exists: make wants a new directory" >&2; exit 2; fi
  mkdir -p "$d"; cd "$d" || exit 1
  for k in identity work other; do ssh-keygen -q -t ed25519 -N '' -C $k -f $k; done
  ssh-keygen -q -t ecdsa -b 256 -N '' -C p256 -f p256
  printf 'hello dromas\n' > m
  printf 'hello irongal1\n' > m.bad
  mk good      identity "$A" +33d 5 -O clear
  mk defopts   identity "$A" +33d 5
  mk crit      identity "$A" +33d 5 -O clear -O force-command=/bin/true
  mk expired   identity "$A" 20200101:20200102 5 -O clear
  mk serial3   identity "$A" +33d 3 -O clear
  mk wrongprin identity "$C" +33d 5 -O clear
  mk otherca   other    "$A" +33d 5 -O clear
  mk p256ca    p256     "$A" +33d 5 -O clear
  mk forever   identity "$A" always:forever 5 -O clear
  # a certificate of the identity's own key: its bare signature wrapped in a certificate, which the protocol refuses
  mkdir -p selfcert; cp identity selfcert/work; cp identity.pub selfcert/work.pub; chmod 600 selfcert/work
  if ssh-keygen -q -s identity -I work -n "$A" -V +33d -z 7 -O clear selfcert/work.pub 2>selfcert/cert.err; then echo "cert selfcert: made"; else echo "cert selfcert: FAILED: $(head -1 selfcert/cert.err | cut -c1-120)"; fi
  for n in good defopts crit expired serial3 wrongprin otherca p256ca forever selfcert; do sgn $n; done
  # the identity's own signature
  mkdir -p bare; ssh-keygen -Y sign -n "$ns" -f identity < m > bare/m.sig 2>/dev/null || : > bare/m.sig
  # signed with the private key's own path, the certificate lying beside it
  ssh-keygen -Y sign -n "$ns" -f good/work < m > good/m.sig.plain 2>/dev/null || : > good/m.sig.plain
  ssh-keygen -L -f good/work-cert.pub 2>&1 | sed -n '/Serial/p;/Valid/p;/Critical/,$p' | tr '\n' ' ' | cut -c1-200; echo
  ssh-keygen -L -f defopts/work-cert.pub 2>&1 | sed -n '/Extensions/,$p' | tr '\n' ' ' | cut -c1-200; echo
  exit 0
fi

cd "$d" || exit 1
t=$(mktemp -d)
trap 'rm -f "$t/as.ca" "$t/as.plain" "$t/as.p256" "$t/krlspec" "$t/krl" "$t/krl.err"; rmdir "$t"' EXIT
printf '%s cert-authority %s\n' "$A" "$(cat identity.pub)" > "$t/as.ca"
printf '%s %s\n'                "$A" "$(cat identity.pub)" > "$t/as.plain"
printf '%s cert-authority %s\n' "$A" "$(cat p256.pub)"     > "$t/as.p256"
printf 'serial: 1-4\n' > "$t/krlspec"
if ssh-keygen -q -k -f "$t/krl" -s identity.pub "$t/krlspec" 2>"$t/krl.err"; then echo "krl: made (serials 1-4 of the identity revoked)"; else echo "krl: FAILED: $(head -1 "$t/krl.err")"; fi

vfy "certified key, identity as cert-authority"            Good    "$t/as.ca"    "$A" "$ns" good/m.sig      m
vfy "same, identity listed as an ordinary key"             refused "$t/as.plain" "$A" "$ns" good/m.sig      m
vfy "same, message altered"                                refused "$t/as.ca"    "$A" "$ns" good/m.sig      m.bad
vfy "same, another namespace"                              refused "$t/as.ca"    "$A" "dromas-msg-v1:$C" good/m.sig m
vfy "certificate for another principal"                    refused "$t/as.ca"    "$A" "$ns" wrongprin/m.sig m
vfy "certificate from another key"                         refused "$t/as.ca"    "$A" "$ns" otherca/m.sig   m
vfy "signed with -f work (the private key's path)"         "?"     "$t/as.ca"    "$A" "$ns" good/m.sig.plain m
vfy "certificate with the five default permit-* extensions" "?"    "$t/as.ca"    "$A" "$ns" defopts/m.sig   m
vfy "certificate with a critical option (force-command)"   "?"     "$t/as.ca"    "$A" "$ns" crit/m.sig      m
vfy "expired certificate, checked now"                     refused "$t/as.ca"    "$A" "$ns" expired/m.sig   m
vfy "expired certificate, -O verify-time inside validity"  "?"     "$t/as.ca"    "$A" "$ns" expired/m.sig   m -O verify-time=20200101120000
vfy "live certificate, -O verify-time before validity"     "?"     "$t/as.ca"    "$A" "$ns" good/m.sig      m -O verify-time=20200101120000
vfy "serial 5 with a KRL revoking serials 1-4"             Good    "$t/as.ca"    "$A" "$ns" good/m.sig      m -r "$t/krl"
vfy "serial 3 with a KRL revoking serials 1-4"             refused "$t/as.ca"    "$A" "$ns" serial3/m.sig   m -r "$t/krl"
vfy "serial 3 with no KRL"                                 Good    "$t/as.ca"    "$A" "$ns" serial3/m.sig   m
vfy "plain P-256 key as the certifying identity"           Good    "$t/as.p256"  "$A" "$ns" p256ca/m.sig    m
vfy "the identity's own signature, identity as an ordinary key" Good "$t/as.plain" "$A" "$ns" bare/m.sig     m
vfy "the identity's own signature, identity as cert-authority"  refused "$t/as.ca" "$A" "$ns" bare/m.sig     m
vfy "a certificate valid forever (the protocol refuses it)"     "?"   "$t/as.ca"    "$A" "$ns" forever/m.sig   m
vfy "a certificate of the identity's own key (refused by the protocol)" "?" "$t/as.ca" "$A" "$ns" selfcert/m.sig m
