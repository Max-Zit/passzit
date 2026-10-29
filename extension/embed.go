// Package extension holds the browser extension's sources (src). The server
// embeds them to offer the extension for download (see internal/extpack).
package extension

import (
	"embed"
	"io/fs"
)

//go:embed src
var files embed.FS

// Src returns the files of extension/src.
func Src() fs.FS {
	sub, err := fs.Sub(files, "src")
	if err != nil {
		panic(err)
	}
	return sub
}
