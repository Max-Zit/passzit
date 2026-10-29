// passzit-server is the PassZit server: it stores the encrypted vaults of
// its users and serves the web vault, the console and the API of the
// browser extensions. It never sees a master password or a decrypted item.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/max-zit/passzit/internal/auth"
	"github.com/max-zit/passzit/internal/logfile"
	"github.com/max-zit/passzit/internal/netacl"
	"github.com/max-zit/passzit/internal/store"
	"github.com/max-zit/passzit/internal/tlsutil"
	"github.com/max-zit/passzit/internal/web"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "PassZit")
		}
	}
	return "/var/lib/passzit"
}

func run() error {
	dataDir := flag.String("data-dir", env("PASSZIT_DATA", defaultDataDir()), "data directory (certificates, secret key, logs)")
	dbURL := flag.String("db", os.Getenv("PASSZIT_DB"), "PostgreSQL URL, e.g. postgres://passzit:…@localhost/passzit")
	devDB := flag.Bool("dev-embedded-db", false, "start a private PostgreSQL in the data directory (development, tests and demos only)")
	listen := flag.String("listen", "", "console address; overrides the saved setting (e.g. 127.0.0.1:8443)")
	devHTTP := flag.String("dev-http", "", "also serve the console over plain HTTP on this loopback address (development only)")
	devNo2FA := flag.Bool("dev-no-2fa", false, "sign in without the second factor (test and demo servers only, needs --dev-embedded-db; shown as a warning and audited)")
	resetACL := flag.Bool("reset-allowlist", false, "allow the console again from the private networks (10/8, 172.16/12, 192.168/16, fc00::/7) and exit")
	unblock := flag.String("unblock-ip", "", "lift the sign-in block of an address (or \"all\") and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("passzit-server", version)
		return nil
	}
	if *devNo2FA && !*devDB {
		return errors.New("--dev-no-2fa works only together with --dev-embedded-db")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	var logOut io.Writer = os.Stdout
	if lw, err := logfile.Open(filepath.Join(*dataDir, "logs", "server.log"), 0o600); err == nil {
		defer lw.Close()
		logOut = io.MultiWriter(os.Stdout, lw)
	}
	log := slog.New(slog.NewTextHandler(logOut, nil))

	if *devDB {
		pg, url, err := startEmbeddedDB(*dataDir)
		if err != nil {
			return fmt.Errorf("embedded database: %w", err)
		}
		defer pg.Stop()
		*dbURL = url
		log.Warn("using the embedded development database", "dir", filepath.Join(*dataDir, "pgdata"))
	}
	if *dbURL == "" {
		return errors.New("database URL required (--db or PASSZIT_DB)")
	}
	st, err := store.Open(ctx, *dbURL)
	if err != nil {
		return err
	}
	defer st.Close()
	key, created, err := store.LoadOrCreateSecretKey(*dataDir)
	if err != nil {
		return fmt.Errorf("secret key: %w", err)
	}
	if err := st.UseSecretKey(key); err != nil {
		return err
	}
	if created {
		log.Warn("created a new secret key; back it up together with the database", "file", filepath.Join(*dataDir, store.SecretKeyFile))
	}

	switch {
	case *resetACL:
		if err := web.ResetMgmtAllowList(ctx, st); err != nil {
			return err
		}
		_ = st.Audit(ctx, "-", "local", "settings.network.reset", "settings", "console allow-list reset to the private networks from the command line")
		fmt.Println("The console allows the private networks again. Restart the service if it is running.")
		return nil
	case *unblock != "":
		n, err := st.Unblock(ctx, *unblock)
		if err != nil {
			return err
		}
		_ = st.Audit(ctx, "-", "local", "login.unblock", "ip:"+*unblock, "sign-in block lifted from the command line")
		fmt.Printf("Lifted %d block(s).\n", n)
		return nil
	}

	srv, err := web.New(ctx, st, log)
	if err != nil {
		return err
	}
	srv.Version = version
	srv.DataDir = *dataDir
	if *devNo2FA {
		srv.DevNo2FA = true
		log.Warn("TEST MODE: two-factor sign-in is switched off (--dev-no-2fa); never use this on a production server")
		_ = st.Audit(ctx, "-", "local", "settings.2fa.off", "server", "server started with --dev-no-2fa: sign-in without the second factor")
	}
	net0, err := srv.Network(ctx)
	if err != nil {
		return err
	}
	if *listen != "" {
		net0.MgmtListen = *listen
	}
	if err := net0.Validate(); err != nil {
		return err
	}
	srv.RunningMgmt = net0.MgmtListen
	srv.ListenOverride = *listen != ""

	cert, err := tlsutil.LoadOrCreate(filepath.Join(*dataDir, "tls"), "console", "PassZit server", 5)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	if n, err := st.UserCount(ctx); err != nil {
		return err
	} else if n == 0 {
		tok := auth.RandomToken(18)
		p := filepath.Join(*dataDir, "setup-token.txt")
		if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
			return err
		}
		srv.SetSetupToken(tok)
		srv.SetupTokenFile = p
		log.Warn("no users yet: open the web vault and finish the setup; the setup token is in the file", "file", p)
	}

	errc := make(chan error, 2)
	var servers []*http.Server
	raw, err := net.Listen("tcp", net0.MgmtListen)
	if err != nil {
		return fmt.Errorf("listener %s: %w", net0.MgmtListen, err)
	}
	l := tls.NewListener(&netacl.Listener{Listener: raw, List: srv.MgmtACL, OnRefuse: func(remote string) {
		log.Debug("connection refused by allow-list", "remote", remote)
	}}, tlsutil.ServerConfig(cert))
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
	servers = append(servers, hs)
	go func() { errc <- hs.Serve(l) }()
	log.Info("listening", "addr", raw.Addr().String())
	if *devHTTP != "" {
		a, ok := netacl.AddrOf(*devHTTP)
		if !ok || !a.IsLoopback() {
			return errors.New("--dev-http must be a loopback address such as 127.0.0.1:8080")
		}
		dh := &http.Server{Addr: *devHTTP, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, dh)
		go func() { errc <- dh.ListenAndServe() }()
		log.Warn("development HTTP console (no TLS)", "addr", *devHTTP)
	}
	log.Info("PassZit server started", "version", version)

	go srv.RunHousekeeping(ctx)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	stop()
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, h := range servers {
		_ = h.Shutdown(shut)
	}
	log.Info("stopped")
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// startEmbeddedDB runs PostgreSQL from the data directory on a fixed
// loopback port (development, tests and demos only).
func startEmbeddedDB(dir string) (*embeddedpostgres.EmbeddedPostgres, string, error) {
	const port = 54349
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().Port(port).
		DataPath(filepath.Join(dir, "pgdata")).RuntimePath(filepath.Join(dir, "pgrt")).
		BinariesPath(filepath.Join(dir, "pgbin")).Database("passzit").Logger(io.Discard))
	// A server that was killed (not stopped) leaves its PostgreSQL running;
	// stop that one first so a restart works.
	if _, err := os.Stat(filepath.Join(dir, "pgdata", "postmaster.pid")); err == nil {
		ctl := filepath.Join(dir, "pgbin", "bin", "pg_ctl")
		if runtime.GOOS == "windows" {
			ctl += ".exe"
		}
		_ = exec.Command(ctl, "stop", "-D", filepath.Join(dir, "pgdata"), "-m", "fast").Run() // #nosec G204 -- our own binary in the data directory
	}
	if err := pg.Start(); err != nil {
		return nil, "", err
	}
	return pg, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/passzit?sslmode=disable", port), nil
}
