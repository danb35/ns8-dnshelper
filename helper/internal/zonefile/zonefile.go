// Package zonefile writes a zone's records as a BIND-format zone file and
// reads one back into records, for the zone import and export of the Records
// page (DESIGN.md, Records editor: Zone file import and export).
package zonefile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
	"github.com/danb35/ns8-dnshelper/helper/internal/txtfmt"
)

// Limits for a zone file to import.
const (
	MaxBytes   = 2 << 20
	MaxRecords = 10000
)

// DefaultTTL is written as $TTL, for records whose TTL is not known (0).
const DefaultTTL = 3600

func fqdn(zone string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), ".")) + "."
}

func isTXT(t string) bool { return t == "TXT" || t == "SPF" }

// Export writes records (names relative to zone, "@" for the apex, as the
// helper reports them) as a zone file. SOA and NS records are written too:
// the file describes the zone; an import leaves them out.
func Export(zone string, recs []contract.Record) string {
	sorted := append([]contract.Record{}, recs...)
	rank := func(r contract.Record) int {
		switch {
		case r.Name == "@" && r.Type == "SOA":
			return 0
		case r.Name == "@" && r.Type == "NS":
			return 1
		case r.Name == "@":
			return 2
		}
		return 3
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Data < b.Data
	})
	var b strings.Builder
	fmt.Fprintf(&b, "; %s, exported by dnshelper\n", strings.TrimSuffix(fqdn(zone), "."))
	fmt.Fprintf(&b, "$ORIGIN %s\n$TTL %d\n", fqdn(zone), DefaultTTL)
	for _, r := range sorted {
		data := r.Data
		if isTXT(r.Type) {
			data = txtfmt.EscapeNonASCII(txtfmt.Quote(data))
		}
		ttl := ""
		if r.TTL > 0 {
			ttl = fmt.Sprint(r.TTL)
		}
		fmt.Fprintf(&b, "%s\t%s\tIN\t%s\t%s\n", r.Name, ttl, r.Type, data)
	}
	return b.String()
}

// Parse reads a zone file for zone. Records the zone file holds but that
// dnshelper never changes (SOA, NS at the apex), records of another class
// and names outside the zone are reported in skipped instead. $INCLUDE is
// refused: it would read files on the node.
func Parse(zone, text string) (recs []contract.Record, skipped []contract.Skipped, err error) {
	if len(text) > MaxBytes {
		return nil, nil, &contract.Error{Code: contract.CodeInvalidRequest,
			Message: fmt.Sprintf("the zone file is larger than %d bytes", MaxBytes)}
	}
	origin := fqdn(zone)
	zp := dns.NewZoneParser(strings.NewReader(text), origin, "")
	zp.SetIncludeAllowed(false)
	zp.SetDefaultTTL(DefaultTTL)
	skip := func(name, typ, reason string) {
		skipped = append(skipped, contract.Skipped{Name: name, Type: typ, Reason: reason})
	}
	recs = []contract.Record{}
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		typ := dns.TypeToString[h.Rrtype]
		if typ == "" {
			typ = fmt.Sprintf("TYPE%d", h.Rrtype)
		}
		owner := strings.ToLower(h.Name)
		var name string
		switch {
		case owner == origin:
			name = "@"
		case strings.HasSuffix(owner, "."+origin):
			name = strings.TrimSuffix(owner, "."+origin)
		default:
			skip(strings.TrimSuffix(owner, "."), typ, "outside the zone")
			continue
		}
		switch {
		case h.Class != dns.ClassINET:
			skip(name, typ, "not of class IN")
			continue
		case typ == "SOA":
			skip(name, typ, "managed by the DNS host")
			continue
		case typ == "NS" && name == "@":
			skip(name, typ, "the zone's own name servers are managed by the DNS host")
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String()))
		if data == "" {
			// the parser accepts "www IN CNAME" with nothing after it
			return nil, nil, &contract.Error{Code: contract.CodeInvalidRequest,
				Message: fmt.Sprintf("zone file: %s %s has no value", name, typ)}
		}
		if isTXT(typ) {
			data = txtfmt.Unquote(data)
		}
		if len(recs) >= MaxRecords {
			return nil, nil, &contract.Error{Code: contract.CodeInvalidRequest,
				Message: fmt.Sprintf("the zone file holds more than %d records", MaxRecords)}
		}
		recs = append(recs, contract.Record{Name: name, Type: typ, TTL: int64(h.Ttl), Data: data})
	}
	if e := zp.Err(); e != nil {
		return nil, nil, &contract.Error{Code: contract.CodeInvalidRequest, Message: "zone file: " + e.Error()}
	}
	return recs, nonNil(skipped), nil
}

func nonNil(s []contract.Skipped) []contract.Skipped {
	if s == nil {
		return []contract.Skipped{}
	}
	return s
}
