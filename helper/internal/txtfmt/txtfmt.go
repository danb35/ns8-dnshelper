// Package txtfmt writes and reads TXT values in zone-file presentation format:
// quoted strings of at most 255 bytes with " and \ escaped, and \DDD for
// bytes outside printable ASCII.
package txtfmt

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Unquote joins the quoted strings of a TXT value and undoes the escapes
// (\" \\ and \DDD). A value that is not quoted is returned as it is.
func Unquote(v string) string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, `"`) {
		return v
	}
	var out []byte
	in := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '"':
			in = !in
		case !in:
			// the space between two strings
		case c == '\\' && i+3 < len(v) && isDigits(v[i+1:i+4]):
			n, _ := strconv.Atoi(v[i+1 : i+4])
			out = append(out, byte(n))
			i += 3
		case c == '\\' && i+1 < len(v):
			i++
			out = append(out, v[i])
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Quote writes a TXT value as quoted strings of at most 255 bytes, split
// between characters, with " and \ escaped.
func Quote(v string) string {
	var parts []string
	for len(v) > 0 || len(parts) == 0 {
		n := len(v)
		if n > 255 {
			n = 255
			for n > 0 && !utf8.RuneStart(v[n]) {
				n--
			}
		}
		chunk := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v[:n])
		parts = append(parts, `"`+chunk+`"`)
		v = v[n:]
	}
	return strings.Join(parts, " ")
}

// EscapeNonASCII writes the bytes of a quoted TXT value outside printable
// ASCII as \DDD ("café" becomes "caf\195\169"), for hosts that refuse or
// mangle them (Cloud DNS refuses them, IONOS turns é into e). txtUnquote
// reads them back.
func EscapeNonASCII(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c > 0x7e {
			fmt.Fprintf(&b, "\\%03d", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
