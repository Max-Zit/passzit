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
	"strings"
	"syscall"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/max-zit/passzit/internal/auth"
	"github.com/max-zit/passzit/internal/backup"
	"github.com/max-zit/passzit/internal/helper"
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

// defaultDownloadsDir is where the packages put programs for download.
func defaultDownloadsDir() string {
	if runtime.GOOS == "windows" {
		if exe, err := os.Executable(); err == nil {
			return filepath.Join(filepath.Dir(exe), "downloads")
		}
		return ""
	}
	return "/usr/share/passzit/downloads"
}

func run() error {
	dataDir := flag.String("data-dir", env("PASSZIT_DATA", defaultDataDir()), "data directory (certificates, secret key, logs)")
	dbURL := flag.String("db", os.Getenv("PASSZIT_DB"), "PostgreSQL URL, e.g. postgres://passzit:…@localhost/passzit")
	devDB := flag.Bool("dev-embedded-db", false, "start a private PostgreSQL in the data directory (development, tests and demos only)")
	listen := flag.String("listen", "", "console address; overrides the saved setting (e.g. 127.0.0.1:8443)")
	downloads := flag.String("downloads-dir", env("PASSZIT_DOWNLOADS", defaultDownloadsDir()), "folder with programs users download (maxzit-launcher.exe)")
	devHTTP := flag.String("dev-http", "", "also serve the console over plain HTTP on this loopback address (development only)")
	devNo2FA := flag.Bool("dev-no-2fa", false, "sign in without the second factor (test and demo servers only, needs --dev-embedded-db; shown as a warning and audited)")
	resetACL := flag.Bool("reset-allowlist", false, "allow the console again from the private networks (10/8, 172.16/12, 192.168/16, fc00::/7) and exit")
	unblock := flag.String("unblock-ip", "", "lift the sign-in block of an address (or \"all\") and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	runHelper := flag.Bool("helper", false, "root helper: handle a request of the console (updates, time zone, network) and exit; started by passzit-helper.service")
	restoreFile := flag.String("restore", "", "restore this backup file (database and data files) and exit; stop the server first")
	restorePass := flag.String("restore-passphrase-file", "", "file with the passphrase of the backup (or set PASSZIT_BACKUP_PASSPHRASE)")
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
	if *runHelper {
		// Its own log in a directory only root can write.
		out := io.Writer(os.Stdout)
		if lw, err := logfile.Open("/var/log/passzit-helper/helper.log", 0o644); err == nil {
			_ = os.Chmod("/var/log/passzit-helper", 0o755) // #nosec G302 -- the console reads it, only root writes
			defer lw.Close()
			out = io.MultiWriter(os.Stdout, lw)
		}
		hlog := slog.New(slog.NewTextHandler(out, nil))
		h := &helper.Helper{DataDir: *dataDir, CacheDir: "/var/cache/passzit", EnvFile: "/etc/passzit/server.env", Binary: "/usr/bin/passzit-server",
			Run: helper.RunCommand, Log: func(format string, args ...any) { hlog.Info(fmt.Sprintf(format, args...)) }}
		return h.Handle(ctx)
	}

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
	if *restoreFile != "" {
		return restoreBackup(ctx, *restoreFile, *restorePass, *dataDir, *dbURL)
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
	srv.DownloadsDir = *downloads
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
	if err := helper.WriteServerInfo(*dataDir, helper.ServerInfo{Version: version, MgmtListen: net0.MgmtListen}); err != nil {
		log.Warn("cannot write the server information for the helper", "err", err)
	}
	log.Info("PassZit server started", "version", version)

	go srv.RunHousekeeping(ctx)
	if !*devDB {
		go srv.RunUpdates(ctx)
	}

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

// restoreBackup puts a backup back (server stopped): the database in one
// transaction, then the data files. The server migrates to its own version
// when it starts.
func restoreBackup(ctx context.Context, file, passFile, dataDir, dbURL string) error {
	pass := os.Getenv("PASSZIT_BACKUP_PASSPHRASE")
	if passFile != "" {
		b, err := os.ReadFile(passFile) // #nosec G304 -- the administrator names the file
		if err != nil {
			return err
		}
		pass = strings.TrimRight(string(b), "\r\n")
	}
	f, err := os.Open(file) // #nosec G304 -- the administrator names the file
	if err != nil {
		return err
	}
	defer f.Close()
	m, err := backup.Restore(ctx, f, pass, dataDir, func(ctx context.Context, r io.Reader) error {
		return store.RestoreDump(ctx, dbURL, r)
	})
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	fmt.Printf("Restored the backup of %s (PassZit %s, %d files). Start the server now.\n",
		m.Created.Local().Format("2006-01-02 15:04"), m.ServerVersion, len(m.Files))
	return nil
}
