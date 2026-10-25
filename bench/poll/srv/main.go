// Minimal empty-poll server: Bearer HMAC check + in-memory {count, epoch} lookup, nothing else.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"net/http"
	"strings"
	"sync"
)

var kServer = make([]byte, 32)
var pool = sync.Pool{New: func() any { return hmac.New(sha256.New, kServer) }}
var counts = map[[32]byte]uint32{} // only boxes WITH mail; empty boxes cost no memory

func main() {
	http.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/") // "", "v1", addr, "messages"
		if len(parts) != 4 || parts[3] != "messages" {
			http.NotFound(w, r)
			return
		}
		var H [32]byte
		if n, err := hex.Decode(H[:], []byte(parts[2])); err != nil || n != 32 {
			http.Error(w, "bad_address", 400)
			return
		}
		auth := r.Header.Get("Authorization")
		got, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(auth, "Bearer drt1_"))
		if err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		h := pool.Get().(hash.Hash)
		h.Reset()
		h.Write([]byte("dromas-token-v1"))
		h.Write(H[:])
		h.Write(binary.BigEndian.AppendUint32(nil, 0))
		ok := subtle.ConstantTimeCompare(h.Sum(nil), got) == 1
		pool.Put(h)
		if !ok {
			http.Error(w, "unauthorized", 401)
			return
		}
		if counts[H] == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
			return
		}
		w.Write([]byte("would query"))
	})
	http.ListenAndServe("127.0.0.1:18777", nil)
}
