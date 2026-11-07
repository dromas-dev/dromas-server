// Command dromas-server is the dromas.dev server.
//
//	dromas-server serve (--bucket B | --bodies-dir DIR) --names NAMES [--listen addr] [options] [limits]
//	dromas-server serve --dev [--listen addr] [limits]
//	dromas-server migrate
//	dromas-server account create [--id NAME] [--unmetered]
//	dromas-server account key --account ID --uses N --ttl D
//	dromas-server account drop --account ID --mailbox ADDR
//	dromas-server limits clear --socket PATH --ip ADDR
//
// The first keeps state in PostgreSQL, found as libpq finds a database, by
// its environment (PGHOST, PGDATABASE, PGUSER, PGPASSWORD, PGSERVICE and the
// rest), and messages' bodies in an S3 bucket,
// with AWS credentials from the usual chain, or a directory (ARCHITECTURE.md
// § Storage); it answers 503 until its feed is followed, loads each mailbox
// into memory on its first use, and exits if the feed loses its place, since
// a restart rebuilds memory.
//
// migrate brings the database's schema up to date, as its owner, before
// serve runs on it: serve and account start only on a schema that holds
// every migration of their build, and change no schema (ARCHITECTURE.md
// § Storage).
//
// --dev keeps everything in memory, with no database: the honest server every
// client tests against. Nothing survives a restart.
// It takes a pass made for any name, unless --names is given.
//
// account is the operator's hand on accounts (PROTOCOL.md §11.16) until
// accounts have users who log in: create one, mint an adopt key for it, or
// drop a mailbox from it.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/dromas-dev/dromas-server/internal/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	log.SetOutput(server.Redacting(os.Stderr)) // so net/http's own lines, and the last error's, are redacted as the server's are
	var err error
	switch {
	case len(os.Args) >= 2 && os.Args[1] == "serve":
		err = serve(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "migrate":
		err = migrate(os.Args[2:])
	case len(os.Args) >= 3 && os.Args[1] == "account":
		err = account(os.Args[2], os.Args[3:])
	case len(os.Args) >= 3 && os.Args[1] == "limits":
		err = limits(os.Args[2], os.Args[3:])
	default:
		fmt.Fprintln(os.Stderr, "usage: dromas-server serve ((--bucket B | --bodies-dir DIR) --names NAMES | --dev) [--listen addr] [--limits FILE] [options]")
		fmt.Fprintln(os.Stderr, "       dromas-server migrate")
		fmt.Fprintln(os.Stderr, "       dromas-server account (create | key | drop) [flags]")
		fmt.Fprintln(os.Stderr, "       dromas-server limits default")
		fmt.Fprintln(os.Stderr, "       dromas-server limits clear --socket PATH --ip ADDR")
		fmt.Fprintln(os.Stderr, "       dromas-server limits top --socket PATH --limit NAME [--count N]")
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dev := fs.Bool("dev", false, "keep everything in memory, with no database")
	listen := fs.String("listen", "127.0.0.1:8080", "comma-separated TCP addresses to listen on, each served alike: a reverse proxy in front spreads its connections across several, and each is one more range of its ephemeral ports")
	bucket := fs.String("bucket", "", "the S3 bucket that keeps messages' bodies, a directory bucket or a general purpose one, with a lifecycle rule that deletes what is older than the message TTL")
	bodiesDir := fs.String("bodies-dir", "", "the directory that keeps messages' bodies, in place of --bucket: shared by several processes only on one host or a shared filesystem")
	sweepEvery := fs.Duration("sweep-interval", 10*time.Minute, "how often the rows past their expiry are deleted, one process at a time, and bodies under --bodies-dir past the message TTL collected (0: never)")
	sweepGrace := fs.Duration("sweep-grace", time.Hour, "how long past its expiry, by the database's clock, a row is kept before the sweep deletes it")
	names := fs.String("names", "", "comma-separated names clients call this server by: the host of its URL, lowercase, with a port only when that is neither 80 nor 443; a pass is taken only for one of them")
	idTypes := fs.String("identity-types", strings.Join(protocol.IdentityTypes(), ","), "comma-separated identity key types a mailbox may register with, of those this build verifies; "+protocol.IdentityEd25519+" is always one of them")
	region := fs.String("region", "us-east-1", "the AWS region of --bucket")
	mailboxCache := fs.Int("mailbox-cache", server.DefaultMailboxCache, "mailbox records held in memory, for sends and reads of a mailbox")
	shard := fs.String("shard", "", "I/N: this process answers only for the mailboxes of shard I of N, N a power of two up to 64, when the reverse proxy in front sends each mailbox's calls to one process by its address: shard I is the addresses whose first character after d_ has a base64url value v with v*N/64 == I; any other mailbox's call is answered 503 (empty: every mailbox)")
	proxies := fs.String("trusted-proxy", "", "comma-separated CIDRs of the reverse proxy in front, if any, whose X-Forwarded-For names the client: its last address, the one the proxy wrote")
	l := server.DefaultLimits()
	fs.IntVar(&l.HeadBytes, "max-header-bytes", l.HeadBytes, "the most of a request's head, its request line and headers, the server reads: what the longest call needs, its pass at the longest a pass can be, and no more; net/http answers a longer one 431 (0: net/http's default)")
	fs.DurationVar(&l.HeadTimeout, "header-timeout", l.HeadTimeout, "how long a request's head, its request line and headers, may take to arrive before any handler sees it (0: off)")
	adminSocket := fs.String("admin-socket", "", "a Unix socket for the operator's commands (dromas-server limits): 0600 from the moment this process makes it, never on the API's listener (empty: none)")
	idle := fs.Duration("idle-timeout", 75*time.Second, "how long an idle keep-alive connection stays open (nginx's default as a server): above the idle timeout of a proxy in front, which may otherwise reuse a connection this one has just closed")
	metricsListen := fs.String("metrics-listen", "", "address to serve the operator's metrics on, at /metrics in Prometheus' text format: a listener of its own, never the API's (empty: none)")
	siteBackend := fs.String("site-backend", "", "the URL of a deployment's own web server, http or https and a host alone, which every request outside /v1/ and /to/ is passed to, as a reverse proxy passes it (empty: none; those paths are 404)")
	limitsPath := fs.String("limits", "", "a file of the runtime-config directory (bind-mounted read-only as a directory, conventionally /config/), e.g. /config/limits.json: the limits, a JSON object of the members dromas-server limits default prints, each optional, over the defaults it prints. Read at start, or serve does not start; read again on SIGHUP and once a minute, and put in force when it differs and holds its form (empty: the defaults)")
	versionPolicy := fs.String("version-policy", "", "a file of the runtime-config directory (bind-mounted read-only as a directory, conventionally /config/), e.g. /config/version-policy.json: the version policy, a JSON object of GET /v1/'s form with no capabilities and no max_certificate_lifetime, which are the server's own. Read at start, or serve does not start; read again on SIGHUP and once a minute, and put in force when it differs and holds its form (empty: no policy)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	base := l // the defaults, with the startup-only flags
	var limitsRead []byte
	if *limitsPath != "" {
		var err error
		if l, limitsRead, err = server.ReadLimits(*limitsPath, base); err != nil {
			return fmt.Errorf("--limits: %s: %w", *limitsPath, err)
		}
	}
	var policy protocol.ServerDocument
	var policyRead []byte
	if *versionPolicy != "" {
		var err error
		if policy, policyRead, err = server.ReadVersionPolicy(*versionPolicy, l); err != nil {
			return fmt.Errorf("--version-policy: %s: %w", *versionPolicy, err)
		}
	}
	logger := log.New(server.Redacting(os.Stderr), "", log.LstdFlags|log.LUTC)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := server.Config{Limits: l, Log: logger, Policy: policy}
	var reg *prometheus.Registry
	if *metricsListen != "" {
		reg = prometheus.NewRegistry()
		reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		cfg.Metrics = server.NewMetrics(reg)
	}
	serving, err := serverNames(*names)
	if err != nil {
		return err
	}
	cfg.Names = serving
	if cfg.Shard, err = server.ParseShard(*shard); err != nil {
		return fmt.Errorf("--shard: %w", err)
	}
	if cfg.Shard.N > 1 {
		logger.Printf("shard %s: answering only for its mailboxes", cfg.Shard)
	}
	for _, t := range strings.Split(*idTypes, ",") {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		if !slices.Contains(protocol.IdentityTypes(), t) {
			return fmt.Errorf("--identity-types: %q is not a key type this build verifies: %s", t, strings.Join(protocol.IdentityTypes(), ", "))
		}
		cfg.IdentityTypes = append(cfg.IdentityTypes, t)
	}
	if !slices.Contains(cfg.IdentityTypes, protocol.IdentityEd25519) {
		return fmt.Errorf("--identity-types: %s must be one of them: it is the type every client makes and verifies", protocol.IdentityEd25519)
	}
	for _, c := range strings.Split(*proxies, ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("--trusted-proxy: %w", err)
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, p)
	}
	if *siteBackend != "" {
		u, err := server.SiteBackend(*siteBackend)
		if err != nil {
			return fmt.Errorf("--site-backend: %w", err)
		}
		cfg.SiteBackend = u
	}
	var start func() error
	switch {
	case *dev:
		if *bucket != "" || *bodiesDir != "" {
			return errors.New("--dev takes no --bucket or --bodies-dir")
		}
		cfg.Store = server.NewMemStore(time.Now)
		logger.Printf("dromas-server --dev on %s (in memory: nothing survives a restart)", *listen)
	case (*bucket == "") == (*bodiesDir == "") || len(cfg.Names) == 0:
		return errors.New("name --bucket or --bodies-dir, and --names, or run --dev")
	default:
		pc := server.PostgresConfig{
			Bucket:        *bucket,
			BodiesDir:     *bodiesDir,
			MailboxCache:  *mailboxCache,
			SweepInterval: *sweepEvery,
			SweepGrace:    *sweepGrace,
			Log:           logger,
			Metrics:       cfg.Metrics,
		}
		where := "bodies in " + *bodiesDir
		if *bucket != "" {
			awsCfg, err := loadAWS(ctx, *region)
			if err != nil {
				return err
			}
			cfg.Metrics.InstrumentAWS(&awsCfg)
			pc.AWS = awsCfg
			where = "bodies in bucket " + *bucket
		}
		fatal := make(chan error, 1)
		pc.Fatal = func(err error) { fatal <- err }
		store, err := server.NewPostgresStore(ctx, pc)
		if err != nil {
			return err
		}
		cfg.Store, cfg.Ready = store, store.Ready
		start = func() error {
			t := time.Now()
			if err := store.Start(ctx); err != nil {
				return fmt.Errorf("following the database: %w", err)
			}
			logger.Printf("following the database (ready in %s); mailboxes load on first use", time.Since(t).Round(time.Millisecond))
			go func() {
				if err := <-fatal; err != nil {
					logger.Printf("%v: exiting, so a restart rebuilds memory", err)
					stop()
				}
			}()
			return nil
		}
		logger.Printf("dromas-server on %s: PostgreSQL, %s", *listen, where)
	}

	api := server.New(cfg)
	// Each runtime file is reloaded on SIGHUP, as Prometheus reloads
	// --config.file, and once a minute, for a mount that changes with no
	// signal (a Kubernetes ConfigMap's symlink swap). Each has a channel of its
	// own: signal.Notify delivers a SIGHUP to every channel it was given.
	for _, f := range []struct {
		path, name string
		reloader   func() *server.Reloader
	}{
		{*versionPolicy, "version policy", func() *server.Reloader { return api.VersionPolicy(*versionPolicy, policyRead) }},
		{*limitsPath, "limits", func() *server.Reloader { return api.Limits(*limitsPath, limitsRead, base) }},
	} {
		if f.path == "" {
			continue
		}
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		go f.reloader().Run(ctx, hup, server.ReloadEvery)
		logger.Printf("%s from %s: reloaded on SIGHUP and each %v", f.name, f.path, server.ReloadEvery)
	}
	if *adminSocket != "" {
		l, err := listenAdmin(*adminSocket)
		if err != nil {
			return err
		}
		admin := &http.Server{Handler: api.AdminHandler(), ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = admin.Serve(l) }()
		defer admin.Close() //nolint:errcheck // the process is ending
		logger.Printf("operator commands on %s", *adminSocket)
	}
	if reg != nil {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		metrics := &http.Server{Addr: *metricsListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		l, err := net.Listen("tcp", *metricsListen)
		if err != nil {
			return fmt.Errorf("--metrics-listen: %w", err)
		}
		go func() { _ = metrics.Serve(l) }()
		defer metrics.Close() //nolint:errcheck // the process is ending
		logger.Printf("metrics on %s", *metricsListen)
	}
	listeners, err := listenAll(*listen)
	if err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	srv := api.HTTPServer(*listen, *idle)
	srv.ConnState = cfg.Metrics.ConnState
	errc := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func() { errc <- srv.Serve(ln) }()
	}
	if start != nil {
		if err := start(); err != nil {
			return err
		}
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shut); err != nil {
		return err
	}
	if start != nil && !cfg.Ready() {
		return errors.New("stopped: memory could not be shown current")
	}
	return nil
}

// listenAll listens on each of a comma-separated list of TCP addresses, for
// one http.Server to serve on every one (Serve per listener; Shutdown closes
// them all). Behind a reverse proxy each connection the proxy holds is one
// 4-tuple, so one proxy address calling one of these is bounded by the
// proxy's range of ephemeral ports; another address here is another range
// (dromas-dev/dromas-server#124 item 6). On an error it closes what it opened.
//
// The connections it accepts send no TCP keep-alive probes (KeepAlive -1;
// net.Listen's default sends one every 15 s), as nginx leaves a listening
// socket's to the operating system's default unless so_keepalive is set:
// each phase of a connection here has a bound of its own, a flag
// (--header-timeout, body_timeout, --idle-timeout, max_wait), which lets a
// peer gone silent go, and a long poll holds nothing but its goroutine and
// its connection.
func listenAll(spec string) ([]net.Listener, error) {
	var ls []net.Listener
	lc := net.ListenConfig{KeepAlive: -1}
	for _, a := range strings.Split(spec, ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		l, err := lc.Listen(context.Background(), "tcp", a)
		if err != nil {
			for _, o := range ls {
				_ = o.Close()
			}
			return nil, err
		}
		ls = append(ls, l)
	}
	if len(ls) == 0 {
		return nil, errors.New("no address")
	}
	return ls, nil
}

// serverNames reads --names, a comma-separated list of the names clients call
// this server by, each a server name in its one form (PROTOCOL.md §8): one that
// carries port 80 or 443 is refused, since a pass never names either.
func serverNames(list string) ([]string, error) {
	var names []string
	for _, n := range strings.Split(list, ",") {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		if err := protocol.CheckServerName(n); err != nil {
			return nil, fmt.Errorf("--names: %q: %w", n, err)
		}
		names = append(names, n)
	}
	return names, nil
}

// loadAWS is the AWS configuration of --bucket: credentials from the usual
// chain, and the SDK's own lines written through the redaction (AWSLogger).
func loadAWS(ctx context.Context, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithLogger(server.AWSLogger(os.Stderr)))
}
