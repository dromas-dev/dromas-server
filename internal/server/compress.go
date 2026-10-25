package server

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Compression: gzip, where it saves bytes for little CPU, and nowhere else
// (ARCHITECTURE.md § Request paths). A box's read is compressed per answer:
// it is base64 in JSON, the one large answer clients ask for often, before
// every post and for each sender in a drain. A site's pages are compressed
// once, at start. Nothing else is: a poll is a 304 or a near-empty page, a
// message's ciphertext does not compress, and a list puts what senders chose
// beside the box's own values in one body, the shape of BREACH (RFC 7457
// §2.6). A request that does not take gzip gets none.

// answerWriters keep the gzip writers of answers: made once each and reused,
// since a new one costs more than the coding of a box's read. Each codes by
// Huffman alone, with no search for repeats: base64 holds almost none, and
// on reads of 1.6 KB and 4.1 KB the search took 1.5 to 1.7 times as long for
// 1.4 to 3.8% of an X25519 read and nothing of a post-quantum one.
var answerWriters = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(nil, gzip.HuffmanOnly)
	return zw
}}

// writeJSONCompressed answers v as writeJSON does, gzipped when the request
// takes gzip and that is smaller, with its Content-Length. Either way it
// says that it varies by Accept-Encoding, so a cache never hands the gzip to
// a client that did not take it.
func writeJSONCompressed(w http.ResponseWriter, r *http.Request, v any) {
	body, err := jsonBytes(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Add("Vary", "Accept-Encoding")
	if acceptsGzip(r.Header.Values("Accept-Encoding")) {
		zw, _ := answerWriters.Get().(*gzip.Writer)
		if zw != nil {
			if gz := gzipWith(zw, body); gz != nil {
				h.Set("Content-Encoding", "gzip")
				body = gz
			}
			answerWriters.Put(zw)
		}
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// gzipWith is b gzipped by zw, or nil when that is no smaller.
func gzipWith(zw *gzip.Writer, b []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(b))
	zw.Reset(&out)
	if _, err := zw.Write(b); err != nil {
		return nil
	}
	if err := zw.Close(); err != nil || out.Len() >= len(b) {
		return nil
	}
	return out.Bytes()
}

// acceptsGzip reports whether a request's Accept-Encoding fields take gzip
// (RFC 9110 §12.5.3): gzip, or its alias x-gzip (§8.4.1.3), with a weight
// above zero, or else "*" with one. A coding named outright outranks "*". No
// field takes none here: a client that asks for no coding gets none, though
// the RFC would allow any. Named more than once, gzip counts by its last
// weight: the RFC gives such a list no meaning.
func acceptsGzip(fields []string) bool {
	named, gz, star := false, false, false
	for _, f := range fields {
		for c := range strings.SplitSeq(f, ",") {
			name, params, _ := strings.Cut(c, ";")
			switch protocol.LowerASCII(strings.TrimSpace(name)) {
			case "gzip", "x-gzip":
				named, gz = true, weighted(params)
			case "*":
				star = weighted(params)
			}
		}
	}
	if named {
		return gz
	}
	return star
}

// weighted reports whether a coding's parameters give it a weight above
// zero: none gives 1, and a weight strconv.ParseFloat does not read gives
// none. One it reads that is no qvalue by RFC 9110 §12.4.2 (1e-3, .5, 2, inf)
// counts by its value, as §2.4 lets a recipient recover it.
func weighted(params string) bool {
	params = strings.TrimSpace(params)
	if params == "" {
		return true
	}
	name, q, ok := strings.Cut(params, "=")
	if !ok || protocol.LowerASCII(strings.TrimSpace(name)) != "q" {
		return false
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(q), 64)
	return err == nil && n > 0
}
