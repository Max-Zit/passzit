// passzit-helper opens remote connections (RDP, SSH, WinBox) with a
// credential from the PassZit browser extension. The browser starts it
// (native messaging) and passes one message on standard input; it answers
// on standard output and exits.
//
//	passzit-helper install --chrome-id <id> [--chrome-id <id>] [--firefox]
//	passzit-helper uninstall
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/passzit/internal/connect"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			exit(install(os.Args[2:]))
		case "uninstall":
			exit(uninstall())
		case "cleanup":
			cleanup(os.Args[2:])
			return
		case "-version", "--version", "version":
			fmt.Println("passzit-helper", version)
			return
		}
	}
	// Started by a browser: the arguments are its origin or manifest.
	serve()
}

func exit(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve() {
	raw, err := connect.ReadMessage(os.Stdin)
	if err != nil {
		_ = connect.WriteMessage(os.Stdout, connect.Response{Error: "unreadable message"})
		return
	}
	resp := handle(raw)
	_ = connect.WriteMessage(os.Stdout, resp)
}

func lookPath(names ...string) (string, error) {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
		for _, dir := range extraDirs() {
			p := filepath.Join(dir, n)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, nil
			}
		}
	}
	return "", errors.New("not found")
}

func handle(raw []byte) connect.Response {
	var r connect.Request
	if err := jsonUnmarshal(raw, &r); err != nil {
		return connect.Response{Error: "unreadable message"}
	}
	if r.Ping {
		return connect.Response{OK: true, Version: version}
	}
	a, err := connect.Plan(r, connect.Env{GOOS: runtime.GOOS, LookPath: lookPath})
	if err != nil {
		return connect.Response{Error: err.Error()}
	}
	if err := run(a); err != nil {
		return connect.Response{Error: err.Error()}
	}
	return a.Response
}

// run writes the secrets, starts the program and leaves the clean-up to a
// detached copy of the helper (the browser may stop this one right away).
func run(a *connect.Action) error {
	var files []string
	args := append([]string(nil), a.Args...)
	for _, s := range a.Secrets {
		f, err := os.CreateTemp("", "pzh-*")
		if err != nil {
			return err
		}
		_ = f.Chmod(0o600)
		_, werr := f.Write(s.Data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		files = append(files, f.Name())
		if werr != nil {
			removeAll(files)
			return werr
		}
		for i := range args {
			if args[i] == s.Arg {
				args[i] = f.Name()
			}
		}
	}
	if a.Cred != nil {
		if err := writeCred(a.Cred); err != nil {
			removeAll(files)
			return fmt.Errorf("the Windows credential could not be stored: %w", err)
		}
	}
	cmd := exec.Command(a.Program, args...) // #nosec G204 -- a known tool with checked host, port and user
	if a.Stdin != "" {
		cmd.Stdin = strings.NewReader(a.Stdin)
	}
	cmd, err := startDetached(cmd, a.Console)
	if err != nil {
		removeAll(files)
		if a.Cred != nil {
			deleteCred(a.Cred.Target)
		}
		return fmt.Errorf("%s could not be started: %w", filepath.Base(a.Program), err)
	}
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
	if len(files) > 0 || a.Cred != nil {
		cargs := []string{"cleanup", strconv.Itoa(int(a.Keep.Seconds()))}
		cargs = append(cargs, files...)
		if a.Cred != nil {
			cargs = append(cargs, "cred:"+a.Cred.Target)
		}
		self, err := os.Executable()
		if err == nil {
			c := exec.Command(self, cargs...) // #nosec G204 -- this program
			_, err = startDetached(c, false)
		}
		if err != nil {
			// Clean up here as a last resort.
			time.Sleep(a.Keep)
			cleanup(cargs[1:])
		}
	}
	return nil
}

// cleanup removes temporary secrets after a while (a detached process).
func cleanup(args []string) {
	if len(args) == 0 {
		return
	}
	secs, _ := strconv.Atoi(args[0])
	if secs < 0 || secs > 300 {
		secs = 30
	}
	time.Sleep(time.Duration(secs) * time.Second)
	for _, a := range args[1:] {
		if t, ok := strings.CutPrefix(a, "cred:"); ok {
			deleteCred(t)
			continue
		}
		// Only files the helper made itself.
		if strings.HasPrefix(filepath.Base(a), "pzh-") && filepath.Dir(a) == filepath.Clean(os.TempDir()) {
			_ = os.Remove(a) // #nosec G703 -- only our own pzh-* files in the temp folder
		}
	}
}

func removeAll(files []string) {
	for _, f := range files {
		_ = os.Remove(f)
	}
}

func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var ids multi
	fs.Var(&ids, "chrome-id", "id of the PassZit extension in Chrome, Edge, Brave, Opera or Vivaldi (may be given more than once)")
	firefox := fs.Bool("firefox", false, "also for Firefox")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(ids) == 0 && !*firefox {
		return errors.New("give --chrome-id <id> (the PassZit extension shows it in its settings) and/or --firefox")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	if err := registerHost(exe, ids, *firefox); err != nil {
		return err
	}
	fmt.Println("The PassZit helper is registered. Switch on \"Open connections\" in the extension's settings.")
	return nil
}

func uninstall() error {
	if err := unregisterHost(); err != nil {
		return err
	}
	fmt.Println("The PassZit helper is no longer registered.")
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }
