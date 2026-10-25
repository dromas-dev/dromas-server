package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"testing"
)

var kServer = make([]byte, 32)
var boxH = make([]byte, 32)

func tokenMsg(epoch uint32) []byte {
	m := append([]byte("dromas-token-v1"), boxH...)
	return binary.BigEndian.AppendUint32(m, epoch)
}

var presented = "drt1_" + base64.RawURLEncoding.EncodeToString(func() []byte {
	h := hmac.New(sha256.New, kServer)
	h.Write(tokenMsg(7))
	return h.Sum(nil)
}())

// Full check as the server would do it per poll: decode the presented token, recompute, constant-time compare.
func BenchmarkTokenCheckHMACFresh(b *testing.B) {
	for i := 0; i < b.N; i++ {
		got, _ := base64.RawURLEncoding.DecodeString(presented[5:])
		h := hmac.New(sha256.New, kServer)
		h.Write(tokenMsg(7))
		if subtle.ConstantTimeCompare(h.Sum(nil), got) != 1 {
			b.Fatal("mismatch")
		}
	}
}

// Same, reusing a keyed HMAC (one per goroutine in a real server).
func BenchmarkTokenCheckHMACReused(b *testing.B) {
	var h hash.Hash = hmac.New(sha256.New, kServer)
	for i := 0; i < b.N; i++ {
		got, _ := base64.RawURLEncoding.DecodeString(presented[5:])
		h.Reset()
		h.Write(tokenMsg(7))
		if subtle.ConstantTimeCompare(h.Sum(nil), got) != 1 {
			b.Fatal("mismatch")
		}
	}
}

// The random-key-in-DB scheme's crypto: hash the presented token (then a lookup, not measured here).
func BenchmarkTokenCheckRandomHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sha256.Sum256([]byte(presented))
	}
}

// Scale: an in-process map lookup of the box's cached {count, epoch}.
func BenchmarkCacheMapLookup(b *testing.B) {
	type entry struct{ count, epoch uint32 }
	m := make(map[[32]byte]entry, 100000)
	var k [32]byte
	for i := 0; i < 100000; i++ {
		binary.BigEndian.PutUint32(k[:], uint32(i))
		m[k] = entry{1, 7}
	}
	binary.BigEndian.PutUint32(k[:], 4242)
	for i := 0; i < b.N; i++ {
		_ = m[k]
	}
}
