package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// An adopt key (PROTOCOL.md §11.16) lets a box join an account. The server
// keeps its SHA-256, as the key of the account's item for it, and never the
// key, so a copy of the accounts table holds none, and a key is shown once,
// when it is made. A secret of 112 bits or more is kept "in a hashed form
// using an approved hashing function", with no salt (NIST SP 800-63B-4
// §3.1.2.2):
//
//	K = "dra1_" + base64url(account ‖ secret), no padding
//
// with secret 32 random bytes. The account is in the key so that adopt reads
// the key's item, (account, 0x04 ‖ SHA-256(K)), with one GetItem. The hash
// is no keyed hash: a key is taken only as itself, the hash's preimage, so
// length extension gives nothing.
const (
	adoptPrefix    = "dra1_"
	adoptSecretLen = 32
)

// NewAdoptKey returns a new adopt key into account, and the hash it is kept
// by.
func NewAdoptKey(account string) (string, [32]byte, error) {
	if !validAccountID(account) {
		return "", [32]byte{}, errors.New("not an account id")
	}
	raw := make([]byte, len(account)+adoptSecretLen)
	copy(raw, account)
	if _, err := rand.Read(raw[len(account):]); err != nil {
		return "", [32]byte{}, err
	}
	k := adoptPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return k, sha256.Sum256([]byte(k)), nil
}

// parseAdopt returns the account an adopt key names and the key's hash, or
// false for a string that is not one this server could have made. Whether it
// made it is the account table's to say.
func parseAdopt(s string) (string, [32]byte, bool) {
	b64, ok := strings.CutPrefix(s, adoptPrefix)
	if !ok {
		return "", [32]byte{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(b64)
	if err != nil || len(raw) <= adoptSecretLen {
		return "", [32]byte{}, false
	}
	account := string(raw[:len(raw)-adoptSecretLen])
	if !validAccountID(account) {
		return "", [32]byte{}, false
	}
	return account, sha256.Sum256([]byte(s)), true
}
