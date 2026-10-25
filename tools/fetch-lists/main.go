// Command fetch-lists downloads the ten upstream hosts-format block
// lists, applies the list rules, and writes the sorted, unique
// domains one per line. It prints the domain count to stdout.
//
// The rules are exact rather than Go's defaults: each file is
// decoded as UTF-8 with invalid bytes dropped, a lone CR ends a line
// as LF and CRLF do, whitespace is Python's str.isspace set (Go's
// plus U+001C to U+001F), and lowercasing maps a character to ASCII
// exactly when Python's str.lower does.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// files are the exact upstream inputs, from the repository root.
var files = []string{
	"drugs.txt",
	"gambling.txt",
	"malware.txt",
	"phishing.txt",
	"piracy.txt",
	"porn.txt",
	"ransomware.txt",
	"redirect.txt",
	"scam.txt",
	"torrent.txt",
}

// labelRE is the list's label rule: 1 to 63 bytes of
// [a-z0-9-], not starting or ending with a hyphen.
var labelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// isPySpace reports whether Python's str.isspace accepts r, which is
// the set str.split and str.strip use with no arguments. It is Go's
// unicode.IsSpace plus U+001C to U+001F.
func isPySpace(r rune) bool {
	if r >= 0x1c && r <= 0x1f {
		return true
	}
	return unicode.IsSpace(r)
}

// pyLower lowercases the way Python's str.lower does as far as the
// result can pass the label rule. A to Z and U+212A KELVIN SIGN are
// the only characters Python lowercases to pure ASCII. Every other
// non-ASCII character stays non-ASCII here, so the label rule rejects
// it, as it rejects Python's lowercase form. strings.ToLower is not
// usable: it maps U+0130 to "i", where Python gives "i" plus U+0307.
func pyLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		if r == 'K' {
			return 'k'
		}
		return r
	}, s)
}

// isLineBreak reports whether r ends a line under Python's universal
// newlines, where LF, CR, and CRLF each end one.
func isLineBreak(r rune) bool {
	return r == '\n' || r == '\r'
}

// domainFromHostsLine cuts the line at the first '#', splits it on
// whitespace, and takes the second field when there are two or more
// fields, else the first. It returns "" for a line with no fields.
func domainFromHostsLine(line string) string {
	line, _, _ = strings.Cut(line, "#")
	fields := strings.FieldsFunc(line, isPySpace)
	if len(fields) == 0 {
		return ""
	}
	if len(fields) >= 2 {
		return fields[1]
	}
	return fields[0]
}

// normalizeDomain applies the list rule. It returns "" when the
// domain is rejected. Lengths are in bytes where Python counts
// characters; the two agree on every domain the label rule accepts,
// because those are ASCII.
func normalizeDomain(raw string) string {
	d := pyLower(strings.TrimFunc(raw, isPySpace))
	d = strings.TrimRight(d, ".")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return ""
	}
	if net.ParseIP(d) != nil {
		return ""
	}
	for _, label := range strings.Split(d, ".") {
		if !labelRE.MatchString(label) {
			return ""
		}
	}
	return d
}

// parse adds every accepted domain in data to seen and returns the
// number of non-empty lines read and domains accepted.
func parse(data []byte, seen map[string]struct{}) (int, int) {
	text := strings.ToValidUTF8(string(data), "")
	lines := strings.FieldsFunc(text, isLineBreak)
	accepted := 0
	for _, line := range lines {
		d := normalizeDomain(domainFromHostsLine(line))
		if d == "" {
			continue
		}
		accepted++
		seen[d] = struct{}{}
	}
	return len(lines), accepted
}

func fetch(client *http.Client, url string, seen map[string]struct{}) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s: %w", url, err)
	}
	lines, accepted := parse(data, seen)
	log.Printf("%s: %d bytes, %d lines, %d domains", url, len(data), lines, accepted)
	return nil
}

func write(path string, domains []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, d := range domains {
		w.WriteString(d)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func main() {
	base := flag.String("base", "https://raw.githubusercontent.com/blocklistproject/Lists", "upstream raw-file URL prefix, without the revision")
	rev := flag.String("rev", "b9b24117611a318f80a359caec454604f707dc57", "upstream revision")
	out := flag.String("out", "denylist.txt", "output path")
	flag.Parse()
	log.SetFlags(0)

	client := &http.Client{Timeout: 5 * time.Minute}
	seen := make(map[string]struct{})
	for _, name := range files {
		url := strings.TrimRight(*base, "/") + "/" + *rev + "/" + name
		if err := fetch(client, url, seen); err != nil {
			log.Fatal(err)
		}
	}

	domains := make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	if err := write(*out, domains); err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(domains))
}
