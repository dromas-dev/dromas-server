package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

var msg = make([]byte, 16384) // a full-size message
var pub ed25519.PublicKey
var sshsigBlob, sshsigSig, rawSig []byte
var armored string

func init() {
	rand.Read(msg)
	var priv ed25519.PrivateKey
	pub, priv, _ = ed25519.GenerateKey(rand.Reader)
	// SSHSIG signs a small blob: magic, namespace, reserved, hash alg,
	// H(message). The namespace is a pass's, dromas-pass-v1:<address>
	// (PROTOCOL.md §8), for an address of 64 hex characters.
	h := sha512.Sum512(msg)
	str := func(b []byte, s string) []byte { return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...) }
	sshsigBlob = str(str(str([]byte("SSHSIG"), "dromas-pass-v1:"+strings.Repeat("0a", 32)), ""), "sha512")
	sshsigBlob = append(binary.BigEndian.AppendUint32(sshsigBlob, uint32(len(h))), h[:]...)
	sshsigSig = ed25519.Sign(priv, sshsigBlob)
	rawSig = ed25519.Sign(priv, msg)
	armored = base64.StdEncoding.EncodeToString(msg)
}

// What the server does per send for an SSHSIG: hash the 16 KiB ciphertext, verify over the small blob.
func BenchmarkVerifySSHSIG16K(b *testing.B) {
	for i := 0; i < b.N; i++ {
		h := sha512.Sum512(msg)
		blob := append(append([]byte{}, sshsigBlob[:len(sshsigBlob)-64]...), h[:]...)
		if !ed25519.Verify(pub, blob, sshsigSig) {
			b.Fatal("bad")
		}
	}
}

// Same, but a garbage signature (the reject path an attacker would drive).
func BenchmarkVerifySSHSIG16KReject(b *testing.B) {
	bad := append([]byte{}, sshsigSig...)
	bad[10] ^= 1
	for i := 0; i < b.N; i++ {
		h := sha512.Sum512(msg)
		blob := append(append([]byte{}, sshsigBlob[:len(sshsigBlob)-64]...), h[:]...)
		if ed25519.Verify(pub, blob, bad) {
			b.Fatal("accepted")
		}
	}
}

func BenchmarkEd25519VerifyOnly(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, sshsigBlob, sshsigSig)
	}
}

// Work the server does whether or not it verifies, for scale.
func BenchmarkSHA256_16K(b *testing.B) { // the dedupe hash / message id
	for i := 0; i < b.N; i++ {
		sha256.Sum256(msg)
	}
}

func BenchmarkBase64Decode16K(b *testing.B) { // de-armoring the ciphertext
	for i := 0; i < b.N; i++ {
		base64.StdEncoding.DecodeString(armored)
	}
}
