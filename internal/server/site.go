package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
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
// off. A backend that does not answer is a 502.
func (s *Server) siteProxy(backend *url.URL) http.Handler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	return &httputil.ReverseProxy{
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
}
