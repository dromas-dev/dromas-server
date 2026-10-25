package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// A site: with -site, a directory of pages served at the root, outside /v1/
// and /to/, the API's and the link page's. No site's content is in this repo:
// a deployment renders its own into a directory and gives the server that.

// siteTypes are the types of the files a site may hold, by extension, and
// whether each is text, which is gzipped. Markdown is plain text to a
// browser, as the stock types of nginx serve it. An icon or a PNG holds an
// image compressed already.
var siteTypes = map[string]struct {
	ctype string
	text  bool
}{
	".html": {"text/html; charset=utf-8", true},
	".txt":  {"text/plain; charset=utf-8", true},
	".md":   {"text/plain; charset=utf-8", true},
	".svg":  {"image/svg+xml", true},
	".ico":  {"image/x-icon", false},
	".png":  {"image/png", false},
}

// Site is a directory's files, read once at start, each answered at its own
// path and nowhere else. A file named index, of any type, answers at its
// directory's path, which ends in a slash, and not at its own name; that
// path without the slash redirects to it, with its query. Every other path
// is 404.
type Site struct {
	pages map[string]*sitePage
	dirs  map[string]string // the path of each directory with an index, by that path without its slash
}

type sitePage struct {
	body, gz           []byte // gz is body gzipped, when it is text and that is smaller
	ctype, etag, gzTag string
	mod                time.Time
}

// LoadSite reads every file under dir, and gzips each text file once, at the
// best compression, since it is done once. dir may be a link to the
// directory, as a web server's root may. A file of a type siteTypes does not
// name, anything but a regular file or a directory, or a file under v1/ or
// to/, where the API and the link page answer and it could never be served
// at its path, is an error: a site is what its renderer wrote, and anything
// else in it is a mistake.
func LoadSite(dir string) (*Site, error) {
	s := &Site{pages: map[string]*sitePage{}, dirs: map[string]string{}}
	zw, err := gzip.NewWriterLevel(nil, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	// WalkDir takes its root by Lstat, so a root that is a link would be
	// refused as a link inside the site is.
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		return nil, err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", dir)
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: not a regular file", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		u := "/" + filepath.ToSlash(rel)
		if strings.HasPrefix(u, "/v1/") || strings.HasPrefix(u, protocol.LinkPath) {
			return fmt.Errorf("%s: a site holds nothing under /v1/ or %s, where the API and the link page answer", path, protocol.LinkPath)
		}
		ext := filepath.Ext(rel)
		typ, ok := siteTypes[ext]
		if !ok {
			return fmt.Errorf("%s: a site holds no %q files", path, ext)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path) //nolint:gosec // a path under the operator's own directory
		if err != nil {
			return err
		}
		if name := filepath.Base(rel); strings.TrimSuffix(name, ext) == "index" {
			u = strings.TrimSuffix(u, name)
			if u != "/" {
				s.dirs[strings.TrimSuffix(u, "/")] = u
			}
		}
		if _, ok := s.pages[u]; ok {
			return fmt.Errorf("%s: a second index of %s", path, u)
		}
		p := &sitePage{body: body, ctype: typ.ctype, etag: entityTag(body), mod: info.ModTime()}
		if typ.text {
			if p.gz = gzipWith(zw, body); p.gz != nil {
				p.gzTag = entityTag(p.gz)
			}
		}
		s.pages[u] = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// entityTag is a strong ETag of b: its hash.
func entityTag(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// ServeHTTP answers a page, with the caching and the conditional answers a
// static file gets (Last-Modified, a strong ETag, 304, ranges), or 404. A
// page with a gzip answers it to a request that takes gzip: bytes of their
// own, with their own ETag, and ranges of them, which is how net/http's
// ServeContent asks for compression to be done (it then leaves a whole
// answer's Content-Length to net/http, which chunks a large one). It is
// routed at "/" for every method, beside /v1/, so it refuses any but GET and
// HEAD itself, as a route of GET alone would.
func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	p := s.pages[r.URL.Path]
	if p == nil {
		if to, ok := s.dirs[r.URL.Path]; ok {
			// Location is a URI reference: the path is escaped, and the
			// query kept, as nginx redirects a directory.
			http.Redirect(w, r, (&url.URL{Path: to, RawQuery: r.URL.RawQuery}).String(), http.StatusMovedPermanently)
			return
		}
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", p.ctype)
	h.Set("Cache-Control", pageMaxAge)
	h.Set("X-Content-Type-Options", "nosniff")
	body, etag := p.body, p.etag
	if p.gz != nil {
		h.Add("Vary", "Accept-Encoding")
		if acceptsGzip(r.Header.Values("Accept-Encoding")) {
			h.Set("Content-Encoding", "gzip")
			body, etag = p.gz, p.gzTag
		}
	}
	h.Set("ETag", etag)
	http.ServeContent(w, r, "", p.mod, bytes.NewReader(body))
}
