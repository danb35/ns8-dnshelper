package registry

import (
	"errors"
	"strings"
	"testing"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// strip mimics the package's read: strings.Trim of the outer quotes.
func strip(s string) string { return strings.Trim(s, `"`) }

func TestHetznerTXTEncodeDecodeRoundTrip(t *testing.T) {
	long := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 12)
	cases := map[string]string{
		"short":             "v=spf1 include:_spf.example.net ~all",
		"long":              long,
		"exactly 255":       strings.Repeat("a", 255),
		"256":               strings.Repeat("a", 256),
		"three strings":     strings.Repeat("b", 600),
		"inner quotes":      `say "hi" and \ leave`,
		"quote at 255":      strings.Repeat("c", 254) + `"` + strings.Repeat("d", 10),
		"backslash at 255":  strings.Repeat("e", 254) + `\` + strings.Repeat("f", 10),
		"utf8 boundary":     strings.Repeat("é", 200), // 400 bytes, 2 bytes per rune
		"space and ; =":     "a; b=c  d",
		"literal quote sep": `x" "y`,
	}
	for name, plain := range cases {
		enc, err := encodeTXT(plain)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.HasPrefix(enc, `"`) || !strings.HasSuffix(enc, `"`) {
			t.Errorf("%s: encoded form must be fully quoted: %.40q", name, enc)
		}
		// no string over 255 bytes
		for _, part := range strings.Split(enc, `" "`) {
			raw := decodeTXT(strip(`"` + part + `"`))
			if len(raw) > 255 {
				t.Errorf("%s: string of %d bytes", name, len(raw))
			}
		}
		if got := decodeTXT(strip(enc)); got != plain {
			t.Errorf("%s: round trip changed the value\n got %.60q\nwant %.60q", name, got, plain)
		}
	}
}

func TestHetznerRefusesValuesTheReadPathCannotRepresent(t *testing.T) {
	for _, v := range []string{`"leading`, `trailing"`} {
		_, err := encodeTXT(v)
		var ce *contract.Error
		if !errors.As(err, &ce) || ce.Code != contract.CodeInvalidRequest {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func TestHetznerDecodeLeavesUnparseableTextAlone(t *testing.T) {
	for _, s := range []string{`no quotes at all`, `a" b`, `x\`, `a" "b" c`} {
		if got := decodeTXT(s); got != s && s != `a" "b" c` {
			t.Errorf("%q became %q", s, got)
		}
	}
	if got := decodeTXT(`a\065b`); got != "aAb" {
		t.Errorf(`\DDD escape: %q`, got)
	}
	if got := decodeTXT(`a\999b`); got != `a\999b` {
		t.Errorf("out-of-range escape must be left alone: %q", got)
	}
}
