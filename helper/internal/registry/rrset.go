package registry

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/libdns/libdns"
)

// Helpers for providers whose API stores record sets (one name and type,
// several values, one TTL) with every value in presentation format: TXT
// quoted and escaped, SRV "0 0 443 target.". Gandi LiveDNS and deSEC work this
// way. The plan functions work out which sets to rewrite; each provider then
// writes them in its own way.

// rrsetState is a set as stored by the provider. Values are in presentation
// format; the name is relative to the zone, "@" for the apex.
type rrsetState struct {
	Name, Type string
	TTL        int
	Values     []string
}

// rrsetChange is a set to write. No values means: remove the set. A TTL of 0
// means none was given.
type rrsetChange struct {
	Name, Type string
	TTL        int
	Values     []string
}

// hasTarget is the set of types whose value ends in a host name.
var hasTarget = map[string]bool{"ALIAS": true, "CNAME": true, "DNAME": true, "MX": true, "NS": true, "SRV": true}

func isTXT(typ string) bool { t := strings.ToUpper(typ); return t == "TXT" || t == "SPF" }

// qualifyTarget makes a target absolute: without a final dot it is relative
// to the zone.
func qualifyTarget(t, zone string) string {
	z := strings.TrimSuffix(zone, ".") + "."
	switch {
	case t == "@":
		return z
	case strings.HasSuffix(t, "."):
		return t
	}
	return t + "." + z
}

// txtUnquote joins the quoted strings of a TXT value and undoes the escapes
// (\" \\ and \DDD). A value that is not quoted is returned as it is.
func txtUnquote(v string) string {
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

// txtQuote writes a TXT value as quoted strings of at most 255 bytes, split
// between characters, with " and \ escaped.
func txtQuote(v string) string {
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

// escapeNonASCII writes the bytes of a quoted TXT value outside printable
// ASCII as \DDD ("café" becomes "caf\195\169"), for hosts that refuse or
// mangle them (Cloud DNS refuses them, IONOS turns é into e). txtUnquote
// reads them back.
func escapeNonASCII(v string) string {
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

// toPresentation converts a libdns value to presentation format: TXT quoted,
// targets given a final dot so that they are not read as relative to the zone.
func toPresentation(rr libdns.RR) (string, error) {
	typ := strings.ToUpper(rr.Type)
	f := strings.Fields(rr.Data)
	switch typ {
	case "TXT", "SPF":
		return txtQuote(rr.Data), nil
	case "MX":
		if len(f) != 2 {
			return "", fmt.Errorf("MX data must be \"priority target\"")
		}
	case "SRV":
		if len(f) != 4 {
			return "", fmt.Errorf("SRV data must be \"priority weight port target\"")
		}
	}
	if hasTarget[typ] && len(f) > 0 {
		f[len(f)-1] = pbFQDN(f[len(f)-1])
		return strings.Join(f, " "), nil
	}
	return rr.Data, nil
}

// fromPresentation renders one value of a set in libdns' text form: TXT
// unquoted and joined, targets absolute.
func fromPresentation(zone string, s rrsetState, v string) libdns.RR {
	typ := strings.ToUpper(s.Type)
	data := v
	switch {
	case isTXT(typ):
		data = txtUnquote(v)
	case hasTarget[typ]:
		if f := strings.Fields(v); len(f) > 0 {
			f[len(f)-1] = qualifyTarget(f[len(f)-1], zone)
			data = strings.Join(f, " ")
		}
	}
	return libdns.RR{Name: gdName(s.Name), Type: typ, TTL: time.Duration(s.TTL) * time.Second, Data: data}
}

// sameRData compares two values in libdns form: TXT exactly, addresses as
// addresses (2001:DB8::0:1 is 2001:db8::1), HTTPS and SVCB without the quotes
// around parameter values (PowerDNS stores alpn="h2,h3" as alpn=h2,h3), other
// types without case and final dots.
func sameRData(typ, a, b string) bool {
	if isTXT(typ) {
		return a == b
	}
	if t := strings.ToUpper(typ); t == "HTTPS" || t == "SVCB" {
		a, b = strings.ReplaceAll(a, `"`, ""), strings.ReplaceAll(b, `"`, "")
	}
	if x, err := netip.ParseAddr(a); err == nil {
		y, err := netip.ParseAddr(b)
		return err == nil && x == y
	}
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

type rrsetKey struct{ typ, name string }

func keyOf(typ, name string) rrsetKey {
	return rrsetKey{strings.ToUpper(typ), strings.ToLower(gdName(name))}
}

// wantedSet is the input for one set: its name as given, the first TTL given
// (in seconds, 0 if none) and the values, without duplicates.
type wantedSet struct {
	name   string
	ttl    int
	rrs    []libdns.RR
	values []string
}

// groupWanted converts recs and splits them by set, in a stable order.
func groupWanted(recs []libdns.Record) (map[rrsetKey]*wantedSet, []rrsetKey, error) {
	m := map[rrsetKey]*wantedSet{}
	var order []rrsetKey
	for _, r := range recs {
		rr := r.RR()
		v, err := toPresentation(rr)
		if err != nil {
			return nil, nil, err
		}
		k := keyOf(rr.Type, rr.Name)
		w, ok := m[k]
		if !ok {
			w = &wantedSet{name: gdName(rr.Name)}
			m[k] = w
			order = append(order, k)
		}
		if w.ttl == 0 && rr.TTL > 0 {
			w.ttl = int(rr.TTL / time.Second)
		}
		dup := false
		for _, have := range w.rrs {
			dup = dup || sameRData(k.typ, have.Data, rr.Data)
		}
		if !dup {
			w.rrs = append(w.rrs, rr)
			w.values = append(w.values, v)
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].name != order[j].name {
			return order[i].name < order[j].name
		}
		return order[i].typ < order[j].typ
	})
	return m, order, nil
}

// planAppend adds the values to their sets, keeping the ones already there.
// A TTL given in the input becomes the TTL of the whole set; without one the
// set keeps its TTL. Sets that already hold every value are left alone.
func planAppend(zone string, have []rrsetState, recs []libdns.Record) ([]rrsetChange, []libdns.Record, error) {
	add, order, err := groupWanted(recs)
	if err != nil {
		return nil, nil, err
	}
	existing := map[rrsetKey]rrsetState{}
	for _, s := range have {
		existing[keyOf(s.Type, s.Name)] = s
	}
	var changes []rrsetChange
	var done []libdns.Record
	for _, k := range order {
		w, s := add[k], existing[k]
		values := append([]string{}, s.Values...)
		for i, rr := range w.rrs {
			dup := false
			for _, v := range s.Values {
				dup = dup || sameRData(k.typ, fromPresentation(zone, s, v).Data, rr.Data)
			}
			if !dup {
				values = append(values, w.values[i])
			}
		}
		ttl := w.ttl
		if ttl == 0 {
			ttl = s.TTL
		}
		if len(values) > len(s.Values) || ttl != s.TTL {
			changes = append(changes, rrsetChange{Name: w.name, Type: k.typ, TTL: ttl, Values: values})
		}
		for _, rr := range w.rrs {
			done = append(done, rr)
		}
	}
	return changes, done, nil
}

// planSet makes the given records the only members of their sets.
func planSet(recs []libdns.Record) ([]rrsetChange, []libdns.Record, error) {
	set, order, err := groupWanted(recs)
	if err != nil {
		return nil, nil, err
	}
	var changes []rrsetChange
	var done []libdns.Record
	for _, k := range order {
		w := set[k]
		changes = append(changes, rrsetChange{Name: w.name, Type: k.typ, TTL: w.ttl, Values: w.values})
		for _, rr := range w.rrs {
			done = append(done, rr)
		}
	}
	return changes, done, nil
}

// planDelete removes the values that match by name and, when the input states
// them, by type, value and TTL. Other values of a set stay; a set left empty
// is removed. Changes keep the set's TTL.
func planDelete(zone string, have []rrsetState, recs []libdns.Record) ([]rrsetChange, []libdns.Record) {
	var changes []rrsetChange
	var deleted []libdns.Record
	for _, s := range have {
		var keep []string
		var drop []libdns.Record
		for _, v := range s.Values {
			h := fromPresentation(zone, s, v)
			match := false
			for _, r := range recs {
				w := r.RR()
				match = match || (strings.EqualFold(gdName(w.Name), h.Name) &&
					(w.Type == "" || strings.EqualFold(w.Type, h.Type)) &&
					(w.Data == "" || sameRData(h.Type, h.Data, w.Data)) &&
					(w.TTL == 0 || w.TTL == h.TTL))
			}
			if match {
				drop = append(drop, h)
			} else {
				keep = append(keep, v)
			}
		}
		if len(drop) > 0 {
			changes = append(changes, rrsetChange{Name: gdName(s.Name), Type: strings.ToUpper(s.Type), TTL: s.TTL, Values: keep})
			deleted = append(deleted, drop...)
		}
	}
	return changes, deleted
}
