package denylist

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// labels joins n labels of the given lengths with dots, using the
// letter a, so the result is listable unless a length rule fails.
func labels(lengths ...int) string {
	parts := make([]string, 0, len(lengths))
	for _, n := range lengths {
		parts = append(parts, strings.Repeat("a", n))
	}
	return strings.Join(parts, ".")
}

func loadFixture(t *testing.T) *Set {
	t.Helper()
	f, err := os.Open("testdata/fixture.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNormalize(t *testing.T) {
	host253 := labels(63, 63, 63, 61)
	host254 := labels(63, 63, 63, 62)
	if len(host253) != 253 || len(host254) != 254 {
		t.Fatalf("bad length helpers: %d %d", len(host253), len(host254))
	}
	tests := []struct {
		in   string
		want string
	}{
		// Core cases for the README's Matching rules.
		{"Example.COM", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com...", "example.com"},
		{"", ""},
		{"localhost", ""},
		{"a..b.com", ""},
		{strings.Repeat("a", 64) + ".com", ""},
		{host254, ""},
		{"ex ample.com", ""},
		{"-lead.com", ""},
		{"lead-.com", ""},
		{"a.-b.com", ""},
		{"\x01example.com\x1f", "example.com"},
		{"\x7fexample.com", ""},
		{" example.com", ""},
		{"Kelvin.com", ""},
		// Edge cases for the same rules.
		{"EXAMPLE.COM.", "example.com"},
		{strings.Repeat("a", 63) + ".com", strings.Repeat("a", 63) + ".com"},
		{host253, host253},
		{host253 + "...", host253},
		{" " + host253 + "\t", host253},
		{"example.com. ", "example.com"},
		{"example.com .", ""},
		{"example.com.\x01.", ""},
		{"example.com\x7f", ""},
		{"example.com\u0085", ""},
		{"example.com　", ""},
		{"İ.com", ""},
		{".", ""},
		{"...", ""},
		{".example.com", ""},
		{"example.com-", ""},
		{"example.-com", ""},
		{"-.example.com", ""},
		{"exa_mple.com", ""},
		{"example.com:443", ""},
		{"a-b.com", "a-b.com"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"1.2.3.4", "1.2.3.4"},
	}
	for _, tc := range tests {
		if got := Normalize(tc.in); got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNormalizeTrimsEveryControlByte checks each byte from 0x00 to
// 0x20 at the start, at the end, and at both ends.
func TestNormalizeTrimsEveryControlByte(t *testing.T) {
	for b := 0; b <= 0x20; b++ {
		c := string([]byte{byte(b)})
		for _, in := range []string{c + "example.com", "example.com" + c, c + "example.com" + c} {
			if got := Normalize(in); got != "example.com" {
				t.Errorf("Normalize(%q) = %q, want %q", in, got, "example.com")
			}
		}
	}
}

func TestDenied(t *testing.T) {
	s := loadFixture(t)
	tests := []struct {
		in   string
		want bool
	}{
		// Core cases for the README's Matching rules.
		{"10bet.com", true},
		{"a.b.evil.com", true},
		{"EVIL.COM.", true},
		{"example.com", false},
		{"notevil.com", false},
		{"localhost", false},
		{"1.2.3.4", false},
		{"-a.10bet.com", false},
		{"\x1f10bet.com\x00", true},
		// Edge cases for the same rules.
		{"12bet.com", true},
		{"a.10bet.com", true},
		{"a.b.c.evil.com", true},
		{"x.10bet.com...", true},
		{"\n10bet.com\r\n", true},
		{"10bet.com.evil", false},
		{"evil.co", false},
		{"a..evil.com", false},
		{"a-.10bet.com", false},
		{"a_b.10bet.com", false},
		{"\x7f10bet.com", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := s.Denied(tc.in); got != tc.want {
			t.Errorf("Denied(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestDeniedBareTLD keeps the bare-TLD probe: a single-label entry
// denies every listable host under it.
func TestDeniedBareTLD(t *testing.T) {
	s, err := Load(strings.NewReader("com\n"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"a.b.example.com", true},
		{"example.net", false},
		{"com", false}, // no dot, so it fails normalization
	}
	for _, tc := range tests {
		if got := s.Denied(tc.in); got != tc.want {
			t.Errorf("Denied(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestLoad(t *testing.T) {
	if got := loadFixture(t).Len(); got != 3 {
		t.Errorf("fixture Len() = %d, want 3", got)
	}

	for _, in := range []string{"b.com\na.com\n", "a.com\na.com\n"} {
		if _, err := Load(strings.NewReader(in)); !errors.Is(err, ErrUnsorted) {
			t.Errorf("Load(%q) error = %v, want ErrUnsorted", in, err)
		}
	}

	s, err := Load(strings.NewReader("\na.com\n\n\nb.com\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 {
		t.Errorf("Len() = %d, want 2", s.Len())
	}
	if !s.Denied("x.b.com") || !s.Denied("a.com") || s.Denied("c.com") {
		t.Errorf("blank-line input matched wrongly")
	}

	s, err = Load(strings.NewReader("a.com\nb.com"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 || !s.Denied("b.com") {
		t.Errorf("input without a final newline: Len() = %d, Denied(b.com) = %v", s.Len(), s.Denied("b.com"))
	}

	s, err = Load(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 || s.Denied("a.com") {
		t.Errorf("empty input: Len() = %d, Denied(a.com) = %v", s.Len(), s.Denied("a.com"))
	}
}

// TestLoadTooLarge lowers the blob bound to show that input past it
// fails at load rather than wrapping an int32 offset.
func TestLoadTooLarge(t *testing.T) {
	saved := maxBlobLen
	defer func() { maxBlobLen = saved }()
	maxBlobLen = len("a.com\nb.com\n")

	s, err := Load(strings.NewReader("a.com\nb.com\n"))
	if err != nil {
		t.Fatalf("input at the bound: %v", err)
	}
	if s.Len() != 2 || !s.Denied("b.com") {
		t.Errorf("input at the bound: Len() = %d, Denied(b.com) = %v", s.Len(), s.Denied("b.com"))
	}

	if _, err := Load(strings.NewReader("a.com\nb.com\nc.com\n")); !errors.Is(err, ErrTooLarge) {
		t.Errorf("input past the bound: error = %v, want ErrTooLarge", err)
	}
}
