package denylist

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The golden corpus records the reference implementation's verdict for each host.
// testdata/golden.tsv holds one row per line, host<TAB>denied|allowed.
// The host field writes a backslash and every byte outside 0x21-0x7e
// as \xHH, so control bytes, spaces, and non-ASCII bytes survive the
// file format. The corpus is the reference: when a row disagrees, the
// Go code is wrong, not the row.
//
// testdata/golden_domains.txt is the slice of the pinned list
// (upstream b9b24117611a318f80a359caec454604f707dc57, over one million
// domains) that the corpus can reach: every listed domain that appears
// in a corpus host between label boundaries. For these hosts it gives
// the same verdicts as the full list, and it keeps the test runnable
// without fetching the list.

// unescapeHost reverses the host-field encoding. It reports false for
// a raw byte the encoding never writes or a malformed escape.
func unescapeHost(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x21 || c > 0x7e {
			return "", false
		}
		if c != '\\' {
			b.WriteByte(c)
			i++
			continue
		}
		if i+4 > len(s) || s[i+1] != 'x' {
			return "", false
		}
		v, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
		if err != nil {
			return "", false
		}
		b.WriteByte(byte(v))
		i += 4
	}
	return b.String(), true
}

func TestGolden(t *testing.T) {
	f, err := os.Open("testdata/golden_domains.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}

	g, err := os.Open("testdata/golden.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	sc := bufio.NewScanner(g)
	rows, denied := 0, 0
	for line := 1; sc.Scan(); line++ {
		field, verdict, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			t.Fatalf("golden.tsv:%d: no tab", line)
		}
		host, ok := unescapeHost(field)
		if !ok {
			t.Fatalf("golden.tsv:%d: bad host field %q", line, field)
		}
		var want bool
		switch verdict {
		case "denied":
			want = true
		case "allowed":
			want = false
		default:
			t.Fatalf("golden.tsv:%d: bad verdict %q", line, verdict)
		}
		rows++
		if want {
			denied++
		}
		if got := s.Denied(host); got != want {
			t.Errorf("golden.tsv:%d: Denied(%q) = %v, reference verdict %s", line, host, got, verdict)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if denied == 0 || denied == rows {
		t.Fatalf("corpus must hold both verdicts: %d rows, %d denied", rows, denied)
	}
	t.Logf("%d rows: %d denied, %d allowed, against %d domains", rows, denied, rows-denied, s.Len())
}
