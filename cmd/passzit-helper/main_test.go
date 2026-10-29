package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHandle(t *testing.T) {
	if r := handle([]byte(`{"v":1,"ping":true}`)); !r.OK || r.Version == "" {
		t.Fatalf("ping %+v", r)
	}
	if r := handle([]byte(`{"v":1,"tool":"ssh","host":"h","evil":1}`)); r.OK || r.Error == "" {
		t.Fatalf("unknown field accepted %+v", r)
	}
	if r := handle([]byte(`{"v":1,"tool":"ssh","host":"-oProxyCommand=x"}`)); r.OK {
		t.Fatal("option as host accepted")
	}
}

func TestCleanupOnlyOwnFiles(t *testing.T) {
	own, err := os.CreateTemp("", "pzh-*")
	if err != nil {
		t.Fatal(err)
	}
	own.Close()
	other := filepath.Join(t.TempDir(), "pzh-not-in-temp")
	_ = os.WriteFile(other, []byte("x"), 0o600)
	cleanup([]string{"0", own.Name(), other})
	if _, err := os.Stat(own.Name()); err == nil {
		t.Error("own file left")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("a file the helper did not make was removed")
	}
}
