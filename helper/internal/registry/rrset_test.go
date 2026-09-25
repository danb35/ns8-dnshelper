package registry

import (
	"strings"
	"testing"
)

func TestTXTQuotingAndChunking(t *testing.T) {
	long := strings.Repeat("a", 250) + `"\` + strings.Repeat("é", 10) + strings.Repeat("b", 300)
	for _, tc := range []struct{ in, sent string }{
		{`v=spf1 -all`, `"v=spf1 -all"`},
		{`a " b \ c`, `"a \" b \\ c"`},
		{"", `""`},
	} {
		if got := txtQuote(tc.in); got != tc.sent {
			t.Errorf("quote %q: %s, want %s", tc.in, got, tc.sent)
		}
		if got := txtUnquote(tc.sent); got != tc.in {
			t.Errorf("unquote %s: %q", tc.sent, got)
		}
	}
	q := txtQuote(long)
	if txtUnquote(q) != long {
		t.Fatal("long value does not round-trip")
	}
	// Each string holds at most 255 bytes once unescaped, and no character is cut.
	for _, part := range strings.Split(q, `" "`) {
		u := txtUnquote(`"` + strings.Trim(part, `"`) + `"`)
		if len(u) > 255 || strings.ContainsRune(u, '�') {
			t.Fatalf("chunk of %d bytes: %q", len(u), u)
		}
	}
	// A provider's own split and a \DDD escape.
	if got := txtUnquote(`"abc" "def\034g\\h"`); got != `abcdef"g\h` {
		t.Fatalf("got %q", got)
	}
	if got := txtUnquote(`not quoted`); got != "not quoted" {
		t.Fatalf("got %q", got)
	}
}

func TestSameRData(t *testing.T) {
	for _, c := range []struct {
		typ, a, b string
		same      bool
	}{
		{"AAAA", "2001:DB8:0:0::1", "2001:db8::1", true},
		{"A", "192.0.2.1", "192.0.2.10", false},
		{"CNAME", "Target.Example.net.", "target.example.net", true},
		{"TXT", "Hello", "hello", false},
		{"SRV", "0 0 443 mail.example.net.", "0 0 443 Mail.example.net", true},
		{"HTTPS", `1 . alpn="h2,h3"`, "1 . alpn=h2,h3", true},
		{"HTTPS", "1 . alpn=h2", "1 . alpn=h3", false},
	} {
		if got := sameRData(c.typ, c.a, c.b); got != c.same {
			t.Errorf("%s %q %q: %v", c.typ, c.a, c.b, got)
		}
	}
}

func TestEscapeNonASCIIForGoogle(t *testing.T) {
	q := escapeNonASCII(txtQuote(`café "x" \ y`))
	if q != `"caf\195\169 \"x\" \\ y"` {
		t.Fatalf("got %s", q)
	}
	if got := txtUnquote(q); got != `café "x" \ y` {
		t.Fatalf("round trip: %q", got)
	}
}
