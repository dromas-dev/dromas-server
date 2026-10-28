package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// A client that forgets `base64 -w0` sends 76-column-wrapped base64 inside a JSON string, and
// encoding/base64 decodes it to the exact bytes (the decoder ignores \r and \n). A measurement,
// not a test of the server: a send's body is the ciphertext itself, raw (PROTOCOL.md §11.10).
func TestWrappedBase64DecodesExactly(t *testing.T) {
	raw := make([]byte, 10440) // a 10 KiB plaintext's binary age file
	rand.Read(raw)
	flat := base64.StdEncoding.EncodeToString(raw)
	var wrapped strings.Builder
	for i := 0; i < len(flat); i += 76 { // GNU base64's default wrap
		end := i + 76
		if end > len(flat) {
			end = len(flat)
		}
		wrapped.WriteString(flat[i:end])
		wrapped.WriteString("\n")
	}
	for name, in := range map[string]string{"flat": flat, "wrapped LF": wrapped.String(), "wrapped CRLF": strings.ReplaceAll(wrapped.String(), "\n", "\r\n")} {
		got, err := base64.StdEncoding.DecodeString(in)
		if err != nil {
			t.Fatalf("%s: decode error: %v", name, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("%s: decoded bytes differ", name)
		}
	}
}
