package registry

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/libdns/hetzner/v2"
	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// hetznerProvider adapts the libdns Hetzner Cloud DNS package (v2.0.1) to what
// libdns documents and what the live API demands. Verified against the API:
//
//   - the API only accepts TXT values in zone-file form: every string in double
//     quotes, quotes and backslashes escaped, no string over 255 bytes;
//   - the package does none of that: it wraps the text in quotes when it is not
//     already quoted at both ends, and on read strips the outer quotes with
//     strings.Trim, leaving `\"` escapes and the `" "` between strings in place.
//
// So every write encodes the plain value into the API form, and every read
// decodes it back. All other methods (ListZones, ...) are promoted unchanged.
type hetznerProvider struct{ *hetzner.Provider }

func (h hetznerProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := h.Provider.GetRecords(ctx, zone)
	return decodeTXTRecords(recs), err
}

func (h hetznerProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	enc, err := encodeTXTRecords(recs)
	if err != nil {
		return nil, err
	}
	out, err := h.Provider.AppendRecords(ctx, zone, enc)
	return decodeTXTRecords(out), err
}

func (h hetznerProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	enc, err := encodeTXTRecords(recs)
	if err != nil {
		return nil, err
	}
	out, err := h.Provider.SetRecords(ctx, zone, enc)
	return decodeTXTRecords(out), err
}

// DeleteRecords receives records that GetRecords returned (decoded), so they are
// encoded again to match what the API stores.
func (h hetznerProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	enc, err := encodeTXTRecords(recs)
	if err != nil {
		return nil, err
	}
	out, err := h.Provider.DeleteRecords(ctx, zone, enc)
	return decodeTXTRecords(out), err
}

func encodeTXTRecords(recs []libdns.Record) ([]libdns.Record, error) {
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		out[i] = r
		if t, ok := r.(libdns.TXT); ok {
			enc, err := encodeTXT(t.Text)
			if err != nil {
				return nil, err
			}
			t.Text = enc
			out[i] = t
		}
	}
	return out, nil
}

func decodeTXTRecords(recs []libdns.Record) []libdns.Record {
	for i, r := range recs {
		if t, ok := r.(libdns.TXT); ok {
			t.Text = decodeTXT(t.Text)
			recs[i] = t
		}
	}
	return recs
}

// encodeTXT turns a plain TXT value into zone-file form: strings of at most 255
// bytes, each quoted with `\` and `"` escaped, separated by a space.
func encodeTXT(s string) (string, error) {
	// The package strips all quotes at both ends when reading, which would eat
	// the closing quote of a value ending in an (escaped) quote character.
	if strings.HasPrefix(s, `"`) || strings.HasSuffix(s, `"`) {
		return "", &contract.Error{Code: contract.CodeInvalidRequest,
			Message: "provider hetzner cannot store a TXT value that begins or ends with a double quote"}
	}
	var parts []string
	for {
		n := len(s)
		if n > 255 {
			n = 255
			for n > 0 && !utf8.RuneStart(s[n]) { // never split a multi-byte character
				n--
			}
		}
		chunk := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s[:n])
		parts = append(parts, `"`+chunk+`"`)
		s = s[n:]
		if s == "" {
			return strings.Join(parts, " "), nil
		}
	}
}

// decodeTXT reverses encodeTXT on what the package returns, which is the stored
// value with its outermost quotes stripped. Anything that does not parse as a
// sequence of quoted strings is returned untouched.
func decodeTXT(s string) string {
	q := `"` + s + `"`
	var out strings.Builder
	i := 0
	for i < len(q) {
		if q[i] != '"' {
			return s
		}
		i++
		closed := false
		for i < len(q) {
			c := q[i]
			switch {
			case c == '\\' && i+1 < len(q):
				if isDigit(q[i+1]) && i+3 < len(q) && isDigit(q[i+2]) && isDigit(q[i+3]) { // \DDD
					v := int(q[i+1]-'0')*100 + int(q[i+2]-'0')*10 + int(q[i+3]-'0')
					if v > 255 {
						return s
					}
					out.WriteByte(byte(v))
					i += 4
				} else {
					out.WriteByte(q[i+1])
					i += 2
				}
			case c == '"':
				closed = true
				i++
			default:
				out.WriteByte(c)
				i++
			}
			if closed {
				break
			}
		}
		if !closed {
			return s
		}
		for i < len(q) && q[i] == ' ' {
			i++
		}
	}
	return out.String()
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
