// extpack builds the PassZit browser extension (see internal/extpack) into
// extension/build/<target> — load it unpacked for testing — and as zip
// files in dist/ for the stores:
//
//	go run ./tools/buildwasm && go run ./tools/extpack -version 0.2.0
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/max-zit/passzit/internal/extpack"
)

func main() {
	version := flag.String("version", "0.0.0", "extension version (x.y.z)")
	flag.Parse()
	for _, target := range extpack.Targets {
		out := filepath.Join("extension", "build", target)
		if err := extpack.Build(extpack.Options{Root: ".", Target: target, Version: *version, Out: out}); err != nil {
			fmt.Fprintln(os.Stderr, "extpack:", err)
			os.Exit(1)
		}
		zip := filepath.Join("dist", fmt.Sprintf("passzit-extension-%s-%s.zip", target, *version))
		if err := extpack.Zip(out, zip); err != nil {
			fmt.Fprintln(os.Stderr, "extpack:", err)
			os.Exit(1)
		}
		fmt.Println("built", out, "and", zip)
	}
}
