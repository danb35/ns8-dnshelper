package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// digitalOceanProvider talks to the DigitalOcean API (v2) itself. The libdns
// digitalocean package (v0.x, libdns v1 API) cannot be used for MX or SRV: it
// sends the whole libdns value ("0 0 443 target.") as the record's data and
// never fills the API's separate priority, weight and port fields, and on read
// it keeps only the data, losing them. Verified against the API (2026-09-24):
//
//   - SRV and MX take priority, weight and port as separate JSON fields, and an
//     explicit 0 is accepted and kept (they are pointers here, so omitempty
//     drops only an absent field, never a zero; see issue #19);
//   - CNAME, MX, SRV and NS targets must be fully qualified, ending in a dot;
//     they are read back without it;
//   - the API refuses a TTL under 30 seconds; with no TTL the zone's default
//     (1800) is used;
//   - TXT values are stored as given, split into 255-byte strings by the name
//     servers; double quotes round-trip, a backslash is refused;
//   - records are single objects with an ID, so appends and deletes touch only
//     the records named, never the rest of the set.
type digitalOceanProvider struct {
	APIToken string
	baseURL  string // overridden in tests
	pageSize int    // records per request; 0 means the default, set in tests
	client   *http.Client
}

const (
	digitalOceanBase   = "https://api.digitalocean.com"
	digitalOceanMinTTL = 30
	digitalOceanPage   = 200
)

// doRecord is a record as the DigitalOcean API represents it.
type doRecord struct {
	ID       int    `json:"id,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Data     string `json:"data"`
	Priority *int   `json:"priority,omitempty"`
	Port     *int   `json:"port,omitempty"`
	Weight   *int   `json:"weight,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	Flags    *int   `json:"flags,omitempty"`
	Tag      string `json:"tag,omitempty"`
}

// do sends one request. DigitalOcean allows 250 requests a minute and answers
// 429 beyond that, so a 429 is retried a few times.
func (p *digitalOceanProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		status, out, err := p.once(ctx, method, path, payload)
		if status != http.StatusTooManyRequests || attempt >= 4 || err != nil {
			return status, out, err
		}
		select {
		case <-ctx.Done():
			return status, out, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (p *digitalOceanProvider) once(ctx context.Context, method, path string, payload []byte) (int, []byte, error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	base := p.baseURL
	if base == "" {
		base = digitalOceanBase
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := p.client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, out, err
}

// fail reports an unexpected answer with DigitalOcean's own message, which
// never contains the token.
func (p *digitalOceanProvider) fail(what string, status int, body []byte) error {
	var e struct {
		Message string `json:"message"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		msg = e.Message
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return fmt.Errorf("%s: DigitalOcean answered %d: %s", what, status, msg)
}

func doDomain(zone string) string { return url.PathEscape(strings.TrimSuffix(zone, ".")) }

func (p *digitalOceanProvider) page() int {
	if p.pageSize > 0 {
		return p.pageSize
	}
	return digitalOceanPage
}

// ListZones lists the domains of the account. A DigitalOcean token cannot be
// limited to some domains, so this is every domain the token can change.
func (p *digitalOceanProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	var zones []libdns.Zone
	for n := 1; ; n++ {
		status, body, err := p.do(ctx, http.MethodGet, fmt.Sprintf("/v2/domains?page=%d&per_page=%d", n, p.page()), nil)
		if err != nil {
			return nil, err
		}
		if status == http.StatusForbidden {
			return nil, &contract.Error{Code: contract.CodeUnsupported, Message: "this DigitalOcean token is not allowed to list domains"}
		}
		if status != http.StatusOK {
			return nil, p.fail("could not list domains", status, body)
		}
		var res struct {
			Domains []struct {
				Name string `json:"name"`
			} `json:"domains"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return nil, fmt.Errorf("could not decode DigitalOcean's answer: %w", err)
		}
		for _, d := range res.Domains {
			zones = append(zones, libdns.Zone{Name: d.Name + "."})
		}
		if len(res.Domains) < p.page() {
			return zones, nil
		}
	}
}

// list reads every record of the zone.
func (p *digitalOceanProvider) list(ctx context.Context, zone string) ([]doRecord, error) {
	var all []doRecord
	for n := 1; ; n++ {
		status, body, err := p.do(ctx, http.MethodGet, fmt.Sprintf("/v2/domains/%s/records?page=%d&per_page=%d", doDomain(zone), n, p.page()), nil)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound {
			return nil, &contract.Error{Code: contract.CodeZoneNotFound,
				Message: "DigitalOcean does not have the domain " + strings.TrimSuffix(zone, ".")}
		}
		if status != http.StatusOK {
			return nil, p.fail("could not get records", status, body)
		}
		var res struct {
			Records []doRecord `json:"domain_records"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return nil, fmt.Errorf("could not decode DigitalOcean's answer: %w", err)
		}
		all = append(all, res.Records...)
		if len(res.Records) < p.page() {
			return all, nil
		}
	}
}

// GetRecords returns the zone's records. The SOA is left out: the API reports
// it with only the zone's TTL as data, not a real SOA value, and it cannot be
// changed.
func (p *digitalOceanProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		if strings.EqualFold(r.Type, "SOA") {
			continue
		}
		out = append(out, r.toLibdns(zone))
	}
	return out, nil
}

// doHasTarget is the set of types whose data is a host name, which the API
// wants fully qualified and returns without the final dot.
var doHasTarget = map[string]bool{"CNAME": true, "MX": true, "NS": true, "SRV": true}

// toLibdns renders the record in libdns' text form: MX is "priority target",
// SRV is "priority weight port target", CAA is `flags tag "value"`.
func (r doRecord) toLibdns(zone string) libdns.Record {
	typ := strings.ToUpper(r.Type)
	data := r.Data
	if doHasTarget[typ] {
		switch {
		case data == "@":
			data = strings.TrimSuffix(zone, ".") + "."
		case !strings.HasSuffix(data, "."):
			data += "."
		}
	}
	switch typ {
	case "MX":
		data = fmt.Sprintf("%d %s", deref(r.Priority), data)
	case "SRV":
		data = fmt.Sprintf("%d %d %d %s", deref(r.Priority), deref(r.Weight), deref(r.Port), data)
	case "CAA":
		data = fmt.Sprintf("%d %s %q", deref(r.Flags), r.Tag, r.Data)
	}
	return libdns.RR{Name: r.Name, Type: typ, TTL: time.Duration(r.TTL) * time.Second, Data: data}
}

// doFromLibdns converts a record to the API form, raising a TTL under
// DigitalOcean's minimum.
func doFromLibdns(rec libdns.Record) (doRecord, error) {
	rr := rec.RR()
	out := doRecord{Type: strings.ToUpper(rr.Type), Name: gdName(rr.Name), Data: rr.Data, TTL: int(rr.TTL / time.Second)}
	if out.TTL > 0 && out.TTL < digitalOceanMinTTL {
		out.TTL = digitalOceanMinTTL
	}
	f := strings.Fields(rr.Data)
	var err error
	switch out.Type {
	case "MX":
		if len(f) != 2 {
			return out, fmt.Errorf("MX data must be \"priority target\"")
		}
		if out.Priority, err = gdInt(f[0]); err != nil {
			return out, err
		}
		out.Data = f[1]
	case "SRV":
		if len(f) != 4 {
			return out, fmt.Errorf("SRV data must be \"priority weight port target\"")
		}
		for i, dst := range []**int{&out.Priority, &out.Weight, &out.Port} {
			if *dst, err = gdInt(f[i]); err != nil {
				return out, err
			}
		}
		out.Data = f[3]
	case "CAA":
		return out, fmt.Errorf("CAA records are not supported for DigitalOcean")
	}
	if doHasTarget[out.Type] && !strings.HasSuffix(out.Data, ".") {
		out.Data += "."
	}
	return out, nil
}

// matches reports whether the existing record r is what want describes: same
// name and, when want states them, the same type, value and TTL.
func (r doRecord) matches(zone string, want libdns.RR) bool {
	have := r.toLibdns(zone).RR()
	return (want.Type == "" || strings.EqualFold(have.Type, want.Type)) && strings.EqualFold(gdName(have.Name), gdName(want.Name)) &&
		(want.Data == "" || doSameData(have.Data, want.Data)) && (want.TTL == 0 || want.TTL == have.TTL)
}

// doSameData compares values, ignoring case and a missing final dot on the
// target, so "10 mail.example.net" matches "10 mail.example.net.".
func doSameData(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func (p *digitalOceanProvider) create(ctx context.Context, zone string, r doRecord) (doRecord, error) {
	status, body, err := p.do(ctx, http.MethodPost, "/v2/domains/"+doDomain(zone)+"/records", r)
	if err != nil {
		return r, err
	}
	if status != http.StatusCreated {
		return r, p.fail("could not create a "+r.Type+" record", status, body)
	}
	var res struct {
		Record doRecord `json:"domain_record"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return r, fmt.Errorf("could not decode DigitalOcean's answer: %w", err)
	}
	return res.Record, nil
}

func (p *digitalOceanProvider) remove(ctx context.Context, zone string, id int) error {
	status, body, err := p.do(ctx, http.MethodDelete, "/v2/domains/"+doDomain(zone)+"/records/"+strconv.Itoa(id), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return p.fail("could not delete a record", status, body)
	}
	return nil
}

func doConvert(recs []libdns.Record) ([]doRecord, error) {
	out := make([]doRecord, len(recs))
	for i, r := range recs {
		var err error
		if out[i], err = doFromLibdns(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// AppendRecords creates the records. It returns those created before an error.
func (p *digitalOceanProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := doConvert(recs)
	if err != nil {
		return nil, err
	}
	var done []libdns.Record
	for _, r := range in {
		c, err := p.create(ctx, zone, r)
		if err != nil {
			return done, err
		}
		done = append(done, c.toLibdns(zone))
	}
	return done, nil
}

// DeleteRecords removes the records that match by name and type and, when the
// input states them, by value and TTL.
func (p *digitalOceanProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	var deleted []libdns.Record
	for _, e := range existing {
		if strings.EqualFold(e.Type, "SOA") {
			continue
		}
		for _, w := range recs {
			if e.matches(zone, w.RR()) {
				if err := p.remove(ctx, zone, e.ID); err != nil {
					return deleted, err
				}
				deleted = append(deleted, e.toLibdns(zone))
				break
			}
		}
	}
	return deleted, nil
}

// SetRecords makes the given records the only members of their sets: members
// with another value are deleted, missing ones created, equal ones left alone.
func (p *digitalOceanProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := doConvert(recs)
	if err != nil {
		return nil, err
	}
	existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	inSet := func(r doRecord) []doRecord {
		var m []doRecord
		for _, x := range in {
			if strings.EqualFold(x.Type, r.Type) && strings.EqualFold(gdName(x.Name), gdName(r.Name)) {
				m = append(m, x)
			}
		}
		return m
	}
	same := func(a, b doRecord) bool {
		return doSameData(a.toLibdns(zone).RR().Data, b.toLibdns(zone).RR().Data) && (b.TTL == 0 || a.TTL == b.TTL)
	}
	kept := make([]bool, len(in))
	for _, e := range existing {
		wanted := inSet(e)
		if len(wanted) == 0 {
			continue // another set
		}
		keep := false
		for i, x := range in {
			if strings.EqualFold(x.Type, e.Type) && strings.EqualFold(gdName(x.Name), gdName(e.Name)) && !kept[i] && same(e, x) {
				kept[i], keep = true, true
				break
			}
		}
		if !keep {
			if err := p.remove(ctx, zone, e.ID); err != nil {
				return nil, err
			}
		}
	}
	out := make([]libdns.Record, 0, len(in))
	for i, r := range in {
		if !kept[i] {
			if _, err := p.create(ctx, zone, r); err != nil {
				return nil, err
			}
		}
		out = append(out, r.toLibdns(zone))
	}
	return out, nil
}
