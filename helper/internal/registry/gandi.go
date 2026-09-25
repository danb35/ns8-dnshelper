package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// gandiProvider talks to the Gandi LiveDNS API (v5) itself. The libdns gandi
// package (v1.1.0) cannot be used: its SetRecords adds a value to the record
// set instead of replacing the set, it sends TXT values unquoted but reads
// them back quoted (so a TXT record cannot be deleted once its set has two
// values), it has no zone list and no request timeout. Verified against the
// API (2026-09-25):
//
//   - the token is a personal access token sent as a Bearer token; a wrong
//     token gets 403, a missing one 401;
//   - LiveDNS stores record sets, not records: PUT
//     /domains/{fqdn}/records/{name}/{type} replaces a set's values and TTL,
//     DELETE removes the set, and both answer 404 for an unknown set; the
//     apex is "@";
//   - every value is one presentation-format string, SRV "0 0 443 target."
//     included, so the zero-value bug of issue #19 cannot occur;
//   - TXT values are quoted and escaped ("a \" b \\ c"); an unquoted value is
//     quoted by Gandi, and a string over 255 bytes is split into several
//     quoted strings, as served by its name servers;
//   - a target without a final dot is relative to the zone;
//   - the TTL is per set, at least 300 seconds; a set written without one
//     gets 10800;
//   - an unknown domain gets 404, lists are paged (per_page, page).
type gandiProvider struct {
	Token   string
	baseURL string // overridden in tests
	perPage int    // 0 means gandiPage, set in tests
	client  *http.Client
}

const (
	gandiBase   = "https://api.gandi.net/v5/livedns"
	gandiMinTTL = 300
	gandiMaxTTL = 2592000
	gandiPage   = 100
)

// gnRRset is a record set as the Gandi API represents it.
type gnRRset struct {
	Name   string   `json:"rrset_name,omitempty"`
	Type   string   `json:"rrset_type,omitempty"`
	TTL    int      `json:"rrset_ttl,omitempty"`
	Values []string `json:"rrset_values"`
}

// do sends one request. Gandi answers 429 when requests come too fast, so
// that is retried a few times after the wait it asks for.
func (g *gandiProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		status, out, wait, err := g.once(ctx, method, path, payload)
		if status != http.StatusTooManyRequests || attempt >= 4 || err != nil {
			return status, out, err
		}
		select {
		case <-ctx.Done():
			return status, out, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (g *gandiProvider) once(ctx context.Context, method, path string, payload []byte) (status int, out []byte, wait time.Duration, err error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	base := g.baseURL
	if base == "" {
		base = gandiBase
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return 0, nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := g.client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, 0, err
	}
	defer resp.Body.Close()
	out, err = io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	wait = 5 * time.Second
	if n, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && n > 0 && n <= 60 {
		wait = time.Duration(n) * time.Second
	}
	return resp.StatusCode, out, wait, err
}

// fail turns an error answer into a structured error where the status says
// what happened. Gandi's messages never contain the token.
func (g *gandiProvider) fail(what string, status int, body []byte) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "Gandi rejected the token, or it may not manage this domain's DNS"}
	case http.StatusNotFound:
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "Gandi LiveDNS has no such domain that this token can see"}
	}
	var a struct {
		Message string `json:"message"`
		Errors  []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"errors"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &a) == nil {
		var parts []string
		if a.Message != "" {
			parts = append(parts, a.Message)
		}
		for _, e := range a.Errors {
			parts = append(parts, e.Name+": "+e.Description)
		}
		if len(parts) > 0 {
			msg = strings.Join(parts, "; ")
		}
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return fmt.Errorf("%s: Gandi answered %d: %s", what, status, msg)
}

func gnDomain(zone string) string { return url.PathEscape(strings.TrimSuffix(zone, ".")) }

// pages reads every page of a list.
func (g *gandiProvider) pages(ctx context.Context, what, path string, each func([]byte) (int, error)) error {
	size := g.perPage
	if size == 0 {
		size = gandiPage
	}
	for page := 1; ; page++ {
		status, body, err := g.do(ctx, http.MethodGet, fmt.Sprintf("%s?per_page=%d&page=%d", path, size, page), nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return g.fail(what, status, body)
		}
		n, err := each(body)
		if err != nil {
			return fmt.Errorf("could not decode Gandi's answer: %w", err)
		}
		if n < size {
			return nil
		}
	}
}

// ListZones lists the domains of the account that use LiveDNS.
func (g *gandiProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	var zones []libdns.Zone
	err := g.pages(ctx, "could not list domains", "/domains", func(b []byte) (int, error) {
		var page []struct {
			FQDN string `json:"fqdn"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			return 0, err
		}
		for _, d := range page {
			zones = append(zones, libdns.Zone{Name: d.FQDN + "."})
		}
		return len(page), nil
	})
	return zones, err
}

// list reads every record set of the zone.
func (g *gandiProvider) list(ctx context.Context, zone string) ([]gnRRset, error) {
	var all []gnRRset
	err := g.pages(ctx, "could not get records", "/domains/"+gnDomain(zone)+"/records", func(b []byte) (int, error) {
		var page []gnRRset
		if err := json.Unmarshal(b, &page); err != nil {
			return 0, err
		}
		all = append(all, page...)
		return len(page), nil
	})
	return all, err
}

func (g *gandiProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	sets, err := g.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []libdns.Record
	for _, s := range sets {
		for _, v := range s.Values {
			out = append(out, gnToLibdns(zone, s, v))
		}
	}
	return out, nil
}

// gnHasTarget is the set of types whose value ends in a host name.
var gnHasTarget = map[string]bool{"ALIAS": true, "CNAME": true, "DNAME": true, "MX": true, "NS": true, "SRV": true}

// gnToLibdns renders one value of a set in libdns' text form: TXT unquoted
// and joined, targets fully qualified.
func gnToLibdns(zone string, s gnRRset, v string) libdns.Record {
	typ := strings.ToUpper(s.Type)
	data := v
	switch {
	case typ == "TXT" || typ == "SPF":
		data = gnUnquoteTXT(v)
	case gnHasTarget[typ]:
		if f := strings.Fields(v); len(f) > 0 {
			f[len(f)-1] = gnQualify(f[len(f)-1], zone)
			data = strings.Join(f, " ")
		}
	}
	return libdns.RR{Name: gdName(s.Name), Type: typ, TTL: time.Duration(s.TTL) * time.Second, Data: data}
}

// gnQualify makes a target read from Gandi absolute: without a final dot it
// is relative to the zone.
func gnQualify(t, zone string) string {
	z := strings.TrimSuffix(zone, ".") + "."
	switch {
	case t == "@":
		return z
	case strings.HasSuffix(t, "."):
		return t
	}
	return t + "." + z
}

// gnUnquoteTXT joins the quoted strings of a TXT value and undoes the
// escapes (\" \\ and \DDD). A value that is not quoted is returned as it is.
func gnUnquoteTXT(v string) string {
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

// gnQuoteTXT writes a TXT value as quoted strings of at most 255 bytes, split
// between characters, with " and \ escaped.
func gnQuoteTXT(v string) string {
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

// gnValue converts a libdns value to Gandi's form: TXT quoted, targets given
// a final dot so that Gandi does not read them as relative to the zone.
func gnValue(rr libdns.RR) (string, error) {
	typ := strings.ToUpper(rr.Type)
	f := strings.Fields(rr.Data)
	switch typ {
	case "TXT", "SPF":
		return gnQuoteTXT(rr.Data), nil
	case "MX":
		if len(f) != 2 {
			return "", fmt.Errorf("MX data must be \"priority target\"")
		}
	case "SRV":
		if len(f) != 4 {
			return "", fmt.Errorf("SRV data must be \"priority weight port target\"")
		}
	}
	if gnHasTarget[typ] && len(f) > 0 {
		f[len(f)-1] = pbFQDN(f[len(f)-1])
		return strings.Join(f, " "), nil
	}
	return rr.Data, nil
}

type gnKey struct{ typ, name string }

func gnKeyOf(typ, name string) gnKey {
	return gnKey{strings.ToUpper(typ), strings.ToLower(gdName(name))}
}

// gnSameData compares two values in libdns form: TXT exactly, other types
// without case and final dots.
func gnSameData(typ, a, b string) bool {
	if t := strings.ToUpper(typ); t == "TXT" || t == "SPF" {
		return a == b
	}
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func gnTTL(d time.Duration) int {
	ttl := int(d / time.Second)
	switch {
	case ttl <= 0:
		return 0
	case ttl < gandiMinTTL:
		return gandiMinTTL
	case ttl > gandiMaxTTL:
		return gandiMaxTTL
	}
	return ttl
}

// put replaces the set (typ, name) with values, or removes it when values is
// empty. A TTL of 0 is left for Gandi to choose.
func (g *gandiProvider) put(ctx context.Context, zone string, k gnKey, name string, ttl int, values []string) error {
	path := "/domains/" + gnDomain(zone) + "/records/" + url.PathEscape(gdName(name)) + "/" + url.PathEscape(k.typ)
	if len(values) == 0 {
		status, body, err := g.do(ctx, http.MethodDelete, path, nil)
		if err != nil {
			return err
		}
		if status != http.StatusNoContent && status != http.StatusOK && status != http.StatusNotFound {
			return g.fail("could not delete "+k.typ+" records", status, body)
		}
		return nil
	}
	status, body, err := g.do(ctx, http.MethodPut, path, gnRRset{TTL: ttl, Values: values})
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return g.fail("could not write "+k.typ+" records", status, body)
	}
	return nil
}

// gnWanted is one set to write: its name as given, TTL and values.
type gnWanted struct {
	name   string
	ttl    int
	rrs    []libdns.RR
	values []string
}

// gnGroup converts recs and splits them by set, in a stable order. The set's
// TTL is the first one given.
func gnGroup(recs []libdns.Record) (map[gnKey]*gnWanted, []gnKey, error) {
	m := map[gnKey]*gnWanted{}
	var order []gnKey
	for _, r := range recs {
		rr := r.RR()
		v, err := gnValue(rr)
		if err != nil {
			return nil, nil, err
		}
		k := gnKeyOf(rr.Type, rr.Name)
		w, ok := m[k]
		if !ok {
			w = &gnWanted{name: rr.Name}
			m[k] = w
			order = append(order, k)
		}
		if w.ttl == 0 {
			w.ttl = gnTTL(rr.TTL)
		}
		dup := false
		for _, have := range w.rrs {
			dup = dup || gnSameData(k.typ, have.Data, rr.Data)
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

// AppendRecords adds the values to their sets, keeping the ones already
// there. A TTL given in the input becomes the TTL of the whole set, as Gandi
// has one TTL per set.
func (g *gandiProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	add, order, err := gnGroup(recs)
	if err != nil {
		return nil, err
	}
	existing, err := g.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	have := map[gnKey]gnRRset{}
	for _, s := range existing {
		have[gnKeyOf(s.Type, s.Name)] = s
	}
	var done []libdns.Record
	for _, k := range order {
		w, s := add[k], have[k]
		values := append([]string{}, s.Values...)
		for i, rr := range w.rrs {
			dup := false
			for _, v := range s.Values {
				dup = dup || gnSameData(k.typ, gnToLibdns(zone, s, v).RR().Data, rr.Data)
			}
			if !dup {
				values = append(values, w.values[i])
			}
		}
		ttl := w.ttl
		if ttl == 0 {
			ttl = s.TTL
		}
		if err := g.put(ctx, zone, k, w.name, ttl, values); err != nil {
			return done, err
		}
		for _, rr := range w.rrs {
			done = append(done, rr)
		}
	}
	return done, nil
}

// SetRecords makes the given records the only members of their sets.
func (g *gandiProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	set, order, err := gnGroup(recs)
	if err != nil {
		return nil, err
	}
	var done []libdns.Record
	for _, k := range order {
		w := set[k]
		if err := g.put(ctx, zone, k, w.name, w.ttl, w.values); err != nil {
			return nil, err
		}
		for _, rr := range w.rrs {
			done = append(done, rr)
		}
	}
	return done, nil
}

// DeleteRecords removes the values that match by name and, when the input
// states them, by type, value and TTL. Other values of a set stay.
func (g *gandiProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	existing, err := g.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	var deleted []libdns.Record
	for _, s := range existing {
		var keep []string
		var drop []libdns.Record
		for _, v := range s.Values {
			have := gnToLibdns(zone, s, v).RR()
			match := false
			for _, r := range recs {
				w := r.RR()
				match = match || (strings.EqualFold(gdName(w.Name), have.Name) &&
					(w.Type == "" || strings.EqualFold(w.Type, have.Type)) &&
					(w.Data == "" || gnSameData(have.Type, have.Data, w.Data)) &&
					(w.TTL == 0 || w.TTL == have.TTL))
			}
			if match {
				drop = append(drop, have)
			} else {
				keep = append(keep, v)
			}
		}
		if len(drop) == 0 {
			continue
		}
		if err := g.put(ctx, zone, gnKeyOf(s.Type, s.Name), s.Name, s.TTL, keep); err != nil {
			return deleted, err
		}
		deleted = append(deleted, drop...)
	}
	return deleted, nil
}
