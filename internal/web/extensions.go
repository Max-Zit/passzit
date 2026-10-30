package web

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/max-zit/passzit/extension"
	"github.com/max-zit/passzit/internal/extpack"
)

// The browser extensions for download: the server packs them from its own
// files (extension/src, static/pz, the catalogs), so they always match the
// server's version.

type extensionsData struct {
	Version, Server string
	Chromium        string // file names
	Firefox         string
}

// Programs in the downloads folder: the MaxZit Launcher (the Windows
// program WatchZit uses too, built in the WatchZit repository) and the
// PassZit helper for Windows; both open RDP, SSH, WinSCP, WinBox, VNC and
// Telnet for the extension.
const (
	launcherFile = "maxzit-launcher.exe"
	helperFile   = "passzit-helper.exe"
)

// download returns the path of a file the console offers ("" when it is
// not on this server).
func (s *Server) download(name string) string {
	if s.DownloadsDir == "" || (name != launcherFile && name != helperFile) {
		return ""
	}
	p := filepath.Join(s.DownloadsDir, name)
	if st, err := os.Stat(p); err != nil || st.IsDir() { // #nosec G703 -- a fixed name in the downloads folder
		return ""
	}
	return p
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	p := s.download(r.PathValue("file"))
	if p == "" {
		s.notFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(p)+`"`)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	http.ServeFile(w, r, p)
}

// extensionVersion is the version the packed extensions get (development
// builds: 0.0.0).
func (s *Server) extensionVersion() string {
	if extpack.ValidVersion(s.Version) {
		return s.Version
	}
	return "0.0.0"
}

func extensionFile(target, version string) string {
	return fmt.Sprintf("passzit-extension-%s-%s.zip", target, version)
}

func (s *Server) handleExtensions(w http.ResponseWriter, r *http.Request) {
	v := s.extensionVersion()
	s.render(w, r, http.StatusOK, "extensions", &Page{Title: "Browser extensions", Nav: "extensions",
		Data: extensionsData{Version: v, Server: s.publicBase(r), Chromium: extensionFile("chromium", v), Firefox: extensionFile("firefox", v)}})
}

var extZips struct {
	sync.Mutex
	m map[string][]byte
}

// extensionZip packs a target once and keeps it in memory.
func (s *Server) extensionZip(target string) ([]byte, error) {
	extZips.Lock()
	defer extZips.Unlock()
	if b, ok := extZips.m[target]; ok {
		return b, nil
	}
	pz, err := fs.Sub(staticFS, "static/pz")
	if err != nil {
		return nil, err
	}
	cats, err := fs.Sub(i18nFS, "i18n")
	if err != nil {
		return nil, err
	}
	files, err := extpack.Files(extpack.Sources{Ext: extension.Src(), Pz: pz, I18n: cats}, extpack.Options{Target: target, Version: s.extensionVersion()})
	if err != nil {
		return nil, err
	}
	b, err := extpack.ZipFiles(files)
	if err != nil {
		return nil, err
	}
	if extZips.m == nil {
		extZips.m = map[string][]byte{}
	}
	extZips.m[target] = b
	return b, nil
}

func (s *Server) handleExtensionDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	for _, target := range extpack.Targets {
		if name != extensionFile(target, s.extensionVersion()) {
			continue
		}
		b, err := s.extensionZip(target)
		if err != nil {
			s.log.Error("packing the browser extension failed", "target", target, "err", err)
			http.Error(w, "the extension could not be packed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("Cache-Control", "private, max-age=3600")
		_, _ = w.Write(b)
		return
	}
	s.notFound(w, r)
}

func (s *Server) handleLauncher(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "launcher", &Page{Title: "MaxZit Launcher", Nav: "launcher", Data: struct{ Launcher, Helper bool }{s.download(launcherFile) != "", s.download(helperFile) != ""}})
}
