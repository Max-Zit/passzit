package web

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type sentMail struct {
	to            []string
	subject, body string
}

type mailbox struct {
	mu   sync.Mutex
	sent []sentMail
}

func (m *mailbox) send(to []string, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMail{to, subject, body})
	return nil
}

// wait returns the first message whose subject contains want.
func (m *mailbox) wait(t *testing.T, want string) sentMail {
	t.Helper()
	for i := 0; i < 50; i++ {
		m.mu.Lock()
		for _, s := range m.sent {
			if strings.Contains(s.subject, want) {
				m.mu.Unlock()
				return s
			}
		}
		m.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no mail %q", want)
	return sentMail{}
}

func TestEmailNotices(t *testing.T) {
	e := newEnv(t)
	admin := e.setupAdmin()
	box := &mailbox{}
	e.srv.MailSender = box.send
	if code, page := admin.get("/settings/email"); code != http.StatusOK || !strings.Contains(page, "SMTP") {
		t.Fatalf("e-mail page: %d", code)
	}
	if code, _ := admin.form("/settings/email", url.Values{"enabled": {"on"}, "host": {"smtp.example.com"}, "port": {"587"}, "security": {"starttls"},
		"from": {"bad address"}, "to": {"it@example.com"}}); code != http.StatusBadRequest {
		t.Fatalf("invalid sender saved: %d", code)
	}
	if code, _ := admin.form("/settings/email", url.Values{"enabled": {"on"}, "host": {"smtp.example.com"}, "port": {"587"}, "security": {"starttls"},
		"username": {"passzit"}, "password": {"smtp-secret"}, "from": {"passzit@example.com"}, "to": {"it@example.com\nboss@example.com"}}); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	saved := e.srv.emailSettings(t.Context())
	if !saved.Enabled || len(saved.To) != 2 || saved.Password == "" || saved.Password == "smtp-secret" {
		t.Fatalf("saved settings: %+v", saved)
	}
	// the test message goes to the administrator
	admin.form("/settings/email/test", nil)
	if m := box.wait(t, "Test message"); len(m.to) != 1 || m.to[0] != admin.email {
		t.Fatalf("test message to %v", m.to)
	}
	// an invitation by e-mail carries its link
	_, page := admin.form("/users/invite", url.Values{"email": {"new@example.com"}, "role": {"user"}, "send_mail": {"on"}})
	m := box.wait(t, "invited")
	if m.to[0] != "new@example.com" || !strings.Contains(m.body, "/invite/") || !strings.Contains(page, "also sent") {
		t.Fatalf("invitation mail: %+v", m)
	}
	// a failed console backup is mailed to the administrators
	e.srv.notifyAdmins(t.Context(), mailText{Subject: "The console backup failed", Lines: [][]any{{"The backup of the PassZit console failed: %s", "disk full"}}}, "/settings/backup")
	if m := box.wait(t, "backup failed"); len(m.to) != 2 || !strings.Contains(m.body, "disk full") {
		t.Fatalf("backup mail: %+v", m)
	}
}

// fakeSMTP accepts one message and returns what it got.
func fakeSMTP(t *testing.T) (addr string, got chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		rd := bufio.NewReader(c)
		say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
		say("220 fake")
		var data strings.Builder
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "DATA"):
				say("354 go")
				for {
					l, err := rd.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				got <- data.String()
				say("250 ok")
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestSendMailSMTP(t *testing.T) {
	e := newEnv(t)
	addr, got := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	cfg := EmailSettings{Enabled: true, Host: host, Port: p, Security: "none", From: "passzit@example.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.srv.sendMail(ctx, cfg, []string{"it@example.com"}, "[PassZit] Prüfung", "Zeile 1\nZeile 2\n"); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	if !strings.Contains(msg, "To: it@example.com") || !strings.Contains(msg, "=?utf-8?q?") || !strings.Contains(msg, "Zeile 2\r\n") {
		t.Fatalf("message: %q", msg)
	}
	// a password never goes over an unencrypted connection
	cfg.Username = "user"
	if err := e.srv.sendMail(ctx, cfg, []string{"it@example.com"}, "x", "y"); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("password over plain SMTP: %v", err)
	}
	if err := e.srv.sendMail(ctx, cfg, []string{"a@b.c\r\nBcc: x@y.z"}, "x", "y"); err == nil {
		t.Fatal("header injection accepted")
	}
}
