// Package extension holds the browser extension's sources (src). The server
// embeds them to offer the extension for download (see internal/extpack).
package extension

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed src
var files embed.FS

//go:embed VERSION
var version string

// Version is the extension's own version (extension/VERSION). It changes
// only when the extension changes: a server release with an unchanged
// extension keeps it, so the browser stores need no new review. Raise it
// whenever extension/src, internal/extpack or the files the extension
// takes from the server (static/pz, the translations) change.
func Version() string { return strings.TrimSpace(version) }

// Src returns the files of extension/src.
func Src() fs.FS {
	sub, err := fs.Sub(files, "src")
	if err != nil {
		panic(err)
	}
	return sub
}
