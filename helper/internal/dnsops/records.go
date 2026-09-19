package dnsops

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

var typeRe = regexp.MustCompile(`^[A-Z0-9]+$`)

// ZoneFQDN returns the zone in the form libdns wants: lowercase, with a
// trailing dot.
func ZoneFQDN(zone string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), ".")) + "."
}

func zoneBare(zone string) string { return strings.TrimSuffix(ZoneFQDN(zone), ".") }

func normName(n string) string {
	n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
	if n == "" {
		return "@"
	}
	return n
}

// normData canonicalizes RDATA so that equivalent spellings compare equal.
func normData(typ, data string) string {
	switch typ {
	case "A", "AAAA":
		if a, err := netip.ParseAddr(strings.TrimSpace(data)); err == nil {
			return a.String()
		}
	case "CNAME", "NS":
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(data), "."))
	case "MX", "SRV":
		f := strings.Fields(data)
		if len(f) > 0 {
			f[len(f)-1] = strings.ToLower(strings.TrimSuffix(f[len(f)-1], "."))
			return strings.Join(f, " ")
		}
	}
	return data
}

func key(r contract.Record) string {
	return normName(r.Name) + "|" + r.Type + "|" + normData(r.Type, r.Data)
}

func groupKey(r contract.Record) string { return normName(r.Name) + "|" + r.Type }

// same reports whether two records are the same record. A TTL of 0 on either
// side means "unspecified" and matches any TTL.
func same(a, b contract.Record) bool {
	return key(a) == key(b) && (a.TTL == 0 || b.TTL == 0 || a.TTL == b.TTL)
}

func contains(list []contract.Record, r contract.Record) bool {
	for _, x := range list {
		if same(x, r) {
			return true
		}
	}
	return false
}

// Normalize validates a consumer-supplied record for the given zone and returns
// it in canonical form (uppercase type, lowercase relative name).
func Normalize(zone string, r contract.Record) (contract.Record, error) {
	typ := strings.ToUpper(strings.TrimSpace(r.Type))
	if typ != "" && !typeRe.MatchString(typ) {
		return r, invalid("invalid record type %q", r.Type)
	}
	if r.TTL < 0 {
		return r, invalid("negative ttl for %q", r.Name)
	}
	name := strings.TrimSpace(r.Name)
	if name == "" {
		return r, invalid("record name is empty; use \"@\" for the zone apex")
	}
	if strings.HasSuffix(name, ".") {
		return r, invalid("record name %q must be relative to the zone, without a trailing dot", r.Name)
	}
	z := zoneBare(zone)
	if ln := strings.ToLower(name); ln == z || strings.HasSuffix(ln, "."+z) {
		return r, invalid("record name %q must be relative to the zone %s", r.Name, z)
	}
	if typ == "TXT" && len(r.Data) >= 2 && strings.HasPrefix(r.Data, `"`) && strings.HasSuffix(r.Data, `"`) {
		return r, invalid("TXT data for %q must be the plain value, not quoted or escaped", r.Name)
	}
	return contract.Record{Name: normName(name), Type: typ, TTL: r.TTL, Data: r.Data}, nil
}

// NormalizeAll normalizes records that must be complete (type and data set).
func NormalizeAll(zone string, in []contract.Record) ([]contract.Record, error) {
	out := make([]contract.Record, 0, len(in))
	for _, r := range in {
		n, err := Normalize(zone, r)
		if err != nil {
			return nil, err
		}
		if n.Type == "" || n.Data == "" {
			return nil, invalid("record %q needs both type and data", r.Name)
		}
		out = append(out, n)
	}
	return out, nil
}

// toLibdns converts a consumer record to the typed libdns record providers
// expect (Address, TXT, SRV, ...). Unknown types stay libdns.RR.
func toLibdns(r contract.Record) (libdns.Record, error) {
	rr := libdns.RR{Name: r.Name, TTL: time.Duration(r.TTL) * time.Second, Type: r.Type, Data: r.Data}
	rec, err := rr.Parse()
	if err != nil {
		return nil, invalid("record %q %s: %v", r.Name, r.Type, err)
	}
	return rec, nil
}

// fromLibdns converts a provider record to the consumer form.
func fromLibdns(r libdns.Record) contract.Record {
	rr := r.RR()
	typ := strings.ToUpper(rr.Type)
	data := rr.Data
	if typ == "TXT" {
		data = rejoinTXT(data)
	}
	return contract.Record{
		Name: normName(rr.Name),
		Type: typ,
		TTL:  int64(rr.TTL / time.Second),
		Data: data,
	}
}

// rejoinTXT undoes the visible chunking some provider packages leave in TXT
// values longer than 255 bytes. Cloudflare, for one, returns the two strings
// of a long DKIM key as `<255 bytes>" "<rest>` (only the outer quotes are
// stripped). A `" "` is treated as a chunk boundary only when every string
// before it is exactly 255 bytes, which a real value all but never matches.
// Only the consumer-facing copy is repaired; writes still hand the provider
// its own records back, which is what its matching needs.
func rejoinTXT(s string) string {
	const sep = `" "`
	if !strings.Contains(s, sep) {
		return s
	}
	parts := strings.Split(s, sep)
	for _, p := range parts[:len(parts)-1] {
		if len(p) != 255 {
			return s
		}
	}
	return strings.Join(parts, "")
}

func invalid(format string, a ...any) *contract.Error {
	return &contract.Error{Code: contract.CodeInvalidRequest, Message: fmt.Sprintf(format, a...)}
}
