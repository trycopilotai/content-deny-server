package denylist

import (
	"bufio"
	"errors"
	"io"
	"math"
	"slices"
	"sort"
	"strings"
)

// Set holds the sorted domain list as one blob plus offsets.
// A map would cost roughly 100-150 MB resident for the
// over one million domains in the current list; this costs under 50 MB resident (measured).
type Set struct {
	blob    []byte
	offsets []int32 // start index of each domain in blob
}

// Normalize lowercases A-Z, trims bytes 0x00-0x20, and strips
// trailing dots. It returns "" when the host is not listable.
func Normalize(host string) string {
	h := lowerASCII(trimControl(host))
	for strings.HasSuffix(h, ".") {
		h = h[:len(h)-1]
	}
	if !listable(h) {
		return ""
	}
	return h
}

// lowerASCII lowercases A-Z only. strings.ToLower is
// Unicode-aware and would also fold non-ASCII letters,
// which the README's Matching rules leave unchanged.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// trimControl removes every leading and trailing byte in
// 0x00-0x20 once. It does not trim DEL (0x7f) or non-ASCII
// spaces, which strings.TrimSpace would.
func trimControl(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] <= 0x20 {
		start++
	}
	for end > start && s[end-1] <= 0x20 {
		end--
	}
	return s[start:end]
}

// listable applies the validation rule in the README's
// Matching rules. A label may contain hyphens but may not
// start or end with one. IP literals are listable here; only
// tools/fetch-lists drops them from the list.
func listable(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	if !strings.Contains(h, ".") {
		return false
	}
	for start := 0; start < len(h); {
		end := strings.IndexByte(h[start:], '.')
		if end < 0 {
			end = len(h)
		} else {
			end += start
		}
		if end-start == 0 || end-start > 63 {
			return false
		}
		if h[start] == '-' || h[end-1] == '-' {
			return false
		}
		for i := start; i < end; i++ {
			c := h[i]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= '0' && c <= '9':
			case c == '-':
			default:
				return false
			}
		}
		start = end + 1
	}
	return true
}

var ErrUnsorted = errors.New("denylist: input is not sorted")

// ErrTooLarge reports input whose blob would not fit the int32
// offsets.
var ErrTooLarge = errors.New("denylist: input exceeds the int32 offset range")

// maxBlobLen bounds the blob so every offset fits in an int32. It
// is a variable only so a test can lower it.
var maxBlobLen = math.MaxInt32

// Load reads one domain per line. Input must already be
// sorted and unique; unsorted input is an error rather than
// something to fix, because binary search depends on it.
func Load(r io.Reader) (*Set, error) {
	s := &Set{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	prev := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if prev != "" && line <= prev {
			return nil, ErrUnsorted
		}
		if len(s.blob)+len(line)+1 > maxBlobLen {
			return nil, ErrTooLarge
		}
		prev = line
		s.offsets = append(s.offsets, int32(len(s.blob)))
		s.blob = append(s.blob, line...)
		s.blob = append(s.blob, '\n')
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// Drop the spare capacity append growth left behind, so the
	// set keeps only the bytes it uses.
	s.blob = slices.Clone(s.blob)
	s.offsets = slices.Clone(s.offsets)
	return s, nil
}

func (s *Set) Len() int { return len(s.offsets) }

func (s *Set) at(i int) string {
	start := int(s.offsets[i])
	end := start
	for s.blob[end] != '\n' {
		end++
	}
	return string(s.blob[start:end])
}

func (s *Set) contains(candidate string) bool {
	i := sort.Search(len(s.offsets), func(i int) bool {
		return s.at(i) >= candidate
	})
	return i < len(s.offsets) && s.at(i) == candidate
}

// Denied applies the README's suffix match. It tests the whole
// normalized host, then drops the leftmost label and repeats,
// so a.b.evil.com tests a.b.evil.com, b.evil.com, evil.com,
// then com. The bare-TLD probe is intentional: the current
// list contains no single-label entries, so it never fires
// today, but removing it would change behavior if one is
// ever added.
func (s *Set) Denied(host string) bool {
	n := Normalize(host)
	if n == "" {
		return false
	}
	for start := 0; start < len(n); {
		if s.contains(n[start:]) {
			return true
		}
		dot := strings.IndexByte(n[start:], '.')
		if dot < 0 {
			return false
		}
		start += dot + 1
	}
	return false
}
