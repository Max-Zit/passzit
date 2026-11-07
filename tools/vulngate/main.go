// Command vulngate reads `govulncheck -format json` on stdin and fails when
// the code calls a vulnerable function, except for vulnerabilities listed
// in the accepted file - each with a date until which it is accepted and
// the reason (a mitigation in our code while no fixed release exists):
//
//	govulncheck -format json ./... | go run ./tools/vulngate .govulncheck-accepted
//
// Lines of the accepted file: "<ID> <YYYY-MM-DD> <reason>"; "#" starts a
// comment. After its date an entry no longer counts, so it is looked at
// again.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type finding struct {
	OSV   string `json:"osv"`
	Trace []struct {
		Module   string `json:"module"`
		Function string `json:"function"`
	} `json:"trace"`
}

func accepted(path string, now time.Time) (map[string]string, error) {
	out := map[string]string{}
	b, err := os.ReadFile(path) // #nosec G304 G703 -- the file named on the command line (a CI tool)
	if err != nil {
		return nil, err
	}
	for n, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 3 {
			return nil, fmt.Errorf("%s:%d: want \"<ID> <YYYY-MM-DD> <reason>\"", path, n+1)
		}
		until, err := time.Parse("2006-01-02", f[1])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n+1, err)
		}
		if now.Before(until.Add(24 * time.Hour)) {
			out[f[0]] = strings.Join(f[2:], " ")
		} else {
			fmt.Printf("%s: accepted only until %s - look at it again\n", f[0], f[1])
		}
	}
	return out, nil
}

func run(r io.Reader, ok map[string]string) (called []string, err error) {
	seen := map[string]bool{}
	d := json.NewDecoder(bufio.NewReader(r))
	for {
		var m struct {
			Finding *finding `json:"finding"`
		}
		if err := d.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("govulncheck output: %w", err)
		}
		f := m.Finding
		if f == nil || len(f.Trace) == 0 || f.Trace[0].Function == "" || seen[f.OSV] {
			continue // only vulnerable functions that are called count
		}
		seen[f.OSV] = true
		if why, ok := ok[f.OSV]; ok {
			fmt.Printf("%s (%s %s): accepted - %s\n", f.OSV, f.Trace[0].Module, f.Trace[0].Function, why)
			continue
		}
		called = append(called, f.OSV+" ("+f.Trace[0].Module+" "+f.Trace[0].Function+")")
	}
	sort.Strings(called)
	return called, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: govulncheck -format json ./... | vulngate <accepted-file>")
		os.Exit(2)
	}
	ok, err := accepted(os.Args[1], time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	called, err := run(os.Stdin, ok)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, c := range called {
		fmt.Println("CALLED:", c)
	}
	if len(called) > 0 {
		fmt.Printf("%d vulnerabilities in called code (details: govulncheck ./...)\n", len(called))
		os.Exit(1)
	}
	fmt.Println("no vulnerable code called (apart from the accepted entries above)")
}
