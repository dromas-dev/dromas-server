package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/dromas-dev/dromas-client/protocol"
)

// A site: with -site-backend, every request outside /v1/ and /to/, the
// API's and the link page's, is passed to a deployment's own web server, as
// a reverse proxy passes it (net/http/httputil), and its answer, a 404 among
// them, comes back as that server sent it. No site's content or logic is in
// this repo.

// SiteBackend reads the URL of a site's web server: http or https and a
// host, with no path, query, fragment or user.
func SiteBackend(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return nil, fmt.Errorf("%q: want http:// or https:// and a host, and nothing more", raw)
	}
	u.Path = ""
	return u, nil
}

// siteProxy passes a request to the web server at backend: its method, path,
// query, headers and body as they came, with the Host the client asked for.
// X-Forwarded-For names the client by the address the limits key on
// (clientIP), X-Forwarded-Host is the request's Host, and X-Forwarded-Proto
// is a trusted proxy's, else this connection's; the Forwarded and
// X-Forwarded-* headers that came with the request are dropped, as Rewrite
// drops them. The backend is asked for the codings the client asked for and
// no other: net/http's transport would ask for gzip itself where the client
// asked for none, and undo it on the way back, so its own compression is
// off. A backend that does not answer is a 502. A path that is the
// server's once decoded and cleaned (serversPath) is 404, and never passed.
func (s *Server) siteProxy(backend *url.URL) http.Handler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backend)
			r.Out.Host = r.In.Host
			r.SetXForwarded()
			r.Out.Header.Set("X-Forwarded-For", s.clientIP(r.In))
			if proto := r.In.Header.Get("X-Forwarded-Proto"); s.fromProxy(r.In) && (proto == "http" || proto == "https") {
				r.Out.Header.Set("X-Forwarded-Proto", proto)
			}
		},
		ErrorLog: s.log,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serversPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

// serversPath reports whether a request's path, decoded (URL.Path) and
// cleaned of dot-segments (path.Clean), is under /v1/ or /to/, or is /v1 or
// /to. The router matches a path's segments as they were sent, so /v1%2Fx
// and /x/%2e%2e/v1/y come to the site; a web server that decodes a path
// before it routes it, as most do, reads them as /v1/x and /v1/y
// (dromas-dev/dromas-client#504 item 1). Under /v1/ and /to/ every answer
// is the server's.
func serversPath(p string) bool {
	p = path.Clean("/" + p)
	for _, tree := range []string{"/v1/", protocol.LinkPath} {
		if strings.HasPrefix(p+"/", tree) {
			return true
		}
	}
	return false
}
