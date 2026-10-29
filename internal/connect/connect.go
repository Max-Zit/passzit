// Package connect is the core of passzit-helper, the small program the
// browser extension starts (native messaging) to open a remote connection
// with a credential from the vault: RDP, SSH or WinBox.
//
// The helper trusts nothing in a message beyond the wish: the tool must be
// known, host, port and user must pass strict character checks (no option
// injection), and secrets never go on a command line where the tool allows
// another way:
//
//   - RDP (Windows): a Windows credential for TERMSRV/<host> that exists for
//     a few seconds while mstsc starts; on Linux xfreerdp reads it from stdin.
//   - SSH with a password: PuTTY reads it from a file only the user can read
//     (-pwfile, PuTTY ≥ 0.77), removed right after the start; without PuTTY
//     OpenSSH starts and the extension puts the password on the clipboard
//     (cleared after the policy's time).
//   - SSH with a key: OpenSSH reads it from a temporary file only the user
//     can read, removed shortly after the start.
//   - WinBox accepts the password only on its command line: the extension
//     warns before (other programs of the same user can see it while WinBox
//     runs).
package connect

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// HostName is the name the extension uses to reach the helper.
const HostName = "com.maxzit.passzit"

// Tools.
const (
	ToolRDP    = "rdp"
	ToolSSH    = "ssh"
	ToolWinBox = "winbox"
)

// Request is a message of the extension.
type Request struct {
	V          int    `json:"v"`
	Tool       string `json:"tool"`
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	User       string `json:"user,omitempty"`
	Password   string `json:"password,omitempty"`
	Key        string `json:"key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	// Ping asks only whether the helper is installed.
	Ping bool `json:"ping,omitempty"`
}

// Response is the helper's answer.
type Response struct {
	OK      bool   `json:"ok"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
	// Copy asks the extension to put this secret ("password" or
	// "passphrase") on the clipboard: the tool asks for it itself.
	Copy string `json:"copy,omitempty"`
}

var (
	hostRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$`)
	userRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@\\\-]{0,63}$`)
)

// ValidHost accepts DNS names, IPv4 and IPv6 addresses (never anything
// that starts with "-").
func ValidHost(h string) bool {
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return !strings.HasPrefix(h, "-")
	}
	return hostRE.MatchString(h) && !strings.Contains(h, "..")
}

// ValidUser accepts plain user names (DOMAIN\user and user@domain too).
func ValidUser(u string) bool { return userRE.MatchString(u) }

// Validate checks a request before anything runs.
func (r *Request) Validate() error {
	if r.V != 1 {
		return errors.New("unknown message version")
	}
	switch r.Tool {
	case ToolRDP, ToolSSH, ToolWinBox:
	default:
		return errors.New("unknown tool")
	}
	if !ValidHost(r.Host) {
		return errors.New("the address is not valid")
	}
	if r.Port < 0 || r.Port > 65535 {
		return errors.New("the port is not valid")
	}
	if r.User != "" && !ValidUser(r.User) {
		return errors.New("the user name is not valid")
	}
	if strings.ContainsAny(r.Password+r.Passphrase, "\x00\r\n") {
		return errors.New("the password contains characters the tools cannot take")
	}
	if len(r.Password) > 1024 || len(r.Passphrase) > 1024 || len(r.Key) > 64<<10 {
		return errors.New("the secret is too long")
	}
	if r.Key != "" && !strings.Contains(r.Key, "PRIVATE KEY-----") {
		return errors.New("the key is not an OpenSSH or PEM private key")
	}
	return nil
}

// ReadMessage reads one native-messaging message (32-bit length in the
// machine's byte order, little-endian on every supported system, then JSON).
func ReadMessage(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("message of %d bytes refused", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

// WriteMessage writes one native-messaging message.
func WriteMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(b))); err != nil { // #nosec G115 -- small JSON answers
		return err
	}
	_, err = w.Write(b)
	return err
}

// TempSecret is a file only the user can read, removed after Keep.
type TempSecret struct {
	Data []byte
	// Arg is the placeholder in Action.Args replaced by the file's path.
	Arg string
}

// WinCred is a Windows credential that exists while the tool starts.
type WinCred struct {
	Target, User, Password string
}

// Action is what the helper does for a request: write the secrets, start
// the program, clean up after Keep.
type Action struct {
	Program  string
	Args     []string
	Console  bool   // a terminal program: give it a window of its own
	Stdin    string // written to the program's standard input
	Secrets  []TempSecret
	Cred     *WinCred
	Keep     time.Duration
	Response Response
}

// Env is the computer the helper runs on (tests replace it).
type Env struct {
	GOOS     string
	LookPath func(names ...string) (string, error)
}

func addr(host string, port, def int) string {
	if port == 0 || port == def {
		return host
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

func target(r Request) string {
	if r.User == "" {
		return r.Host
	}
	return r.User + "@" + r.Host
}

// Plan works out what to do for a request (nothing runs here).
func Plan(r Request, env Env) (*Action, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	host := strings.Trim(r.Host, "[]")
	switch r.Tool {
	case ToolRDP:
		if env.GOOS == "windows" {
			p, err := env.LookPath("mstsc.exe")
			if err != nil {
				return nil, errors.New("the Remote Desktop client (mstsc) is not installed")
			}
			a := &Action{Program: p, Args: []string{"/v:" + addr(r.Host, r.Port, 3389)}, Keep: 20 * time.Second, Response: Response{OK: true}}
			if r.User != "" && r.Password != "" {
				a.Cred = &WinCred{Target: "TERMSRV/" + host, User: r.User, Password: r.Password}
			}
			return a, nil
		}
		p, err := env.LookPath("xfreerdp3", "xfreerdp", "sdl-freerdp3", "sdl-freerdp")
		if err != nil {
			return nil, errors.New("no RDP client (xfreerdp) is installed")
		}
		a := &Action{Program: p, Args: []string{"/v:" + addr(r.Host, r.Port, 3389), "/cert:tofu"}, Response: Response{OK: true}}
		if r.User != "" {
			a.Args = append(a.Args, "/u:"+r.User)
		}
		if r.Password != "" {
			a.Args = append(a.Args, "/from-stdin")
			a.Stdin = r.Password + "\n"
		}
		return a, nil
	case ToolSSH:
		port := r.Port
		if port == 0 {
			port = 22
		}
		if r.Key != "" {
			ssh, err := env.LookPath("ssh.exe", "ssh")
			if err != nil {
				return nil, errors.New("OpenSSH (ssh) is not installed")
			}
			a := &Action{Program: ssh, Console: true, Args: []string{"-i", "{key}", "-o", "IdentitiesOnly=yes", "-p", strconv.Itoa(port), "--", target(r)},
				Secrets: []TempSecret{{Data: []byte(strings.TrimRight(r.Key, "\n") + "\n"), Arg: "{key}"}}, Keep: 30 * time.Second, Response: Response{OK: true}}
			if r.Passphrase != "" {
				a.Response.Copy = "passphrase"
			}
			return terminal(a, env)
		}
		if r.Password != "" && env.GOOS == "windows" {
			if putty, err := env.LookPath("putty.exe"); err == nil {
				return &Action{Program: putty, Args: []string{"-ssh", "-P", strconv.Itoa(port), "-pwfile", "{pw}", target(r)},
					Secrets: []TempSecret{{Data: []byte(r.Password), Arg: "{pw}"}}, Keep: 15 * time.Second, Response: Response{OK: true}}, nil
			}
		}
		ssh, err := env.LookPath("ssh.exe", "ssh")
		if err != nil {
			return nil, errors.New("neither PuTTY nor OpenSSH (ssh) is installed")
		}
		a := &Action{Program: ssh, Console: true, Args: []string{"-p", strconv.Itoa(port), "--", target(r)}, Response: Response{OK: true}}
		if r.Password != "" {
			a.Response.Copy = "password" // OpenSSH has no safe way to take a password
		}
		return terminal(a, env)
	case ToolWinBox:
		if env.GOOS != "windows" {
			return nil, errors.New("WinBox is started only on Windows")
		}
		p, err := env.LookPath("winbox64.exe", "winbox.exe")
		if err != nil {
			return nil, errors.New("WinBox is not installed (put winbox64.exe on the PATH)")
		}
		args := []string{addr(r.Host, r.Port, 8291)}
		if r.User != "" {
			args = append(args, r.User, r.Password)
		}
		return &Action{Program: p, Args: args, Response: Response{OK: true}}, nil
	}
	return nil, errors.New("unknown tool")
}

// terminal puts a console program into a terminal window on Linux and
// macOS (Windows gives it a console of its own).
func terminal(a *Action, env Env) (*Action, error) {
	if env.GOOS == "windows" {
		return a, nil
	}
	if env.GOOS == "darwin" {
		return nil, errors.New("opening a terminal is not supported on macOS yet")
	}
	t, err := env.LookPath("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm")
	if err != nil {
		return nil, errors.New("no terminal program found")
	}
	args := []string{"-e"}
	if strings.HasSuffix(t, "gnome-terminal") {
		args = []string{"--"}
	}
	a.Args = append(append(args, a.Program), a.Args...)
	a.Program, a.Console = t, false
	return a, nil
}
