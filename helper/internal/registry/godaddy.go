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

	"github.com/libdns/libdns"
)

// goDaddyProvider talks to the GoDaddy Domains API (v1) itself. The libdns
// godaddy package (v1.1.0) cannot be used for writing, verified against the API:
//
//   - AppendRecords PUTs one record to /records/{type}/{name}, and that call
//     replaces the whole record set, so appending removes the other records
//     with the same name and type;
//   - DeleteRecords deletes the whole record set whatever the value;
//   - it drops the priority of MX records and cannot write SRV records (the API
//     wants service, protocol, port and weight as separate fields).
//
// GoDaddy only offers whole-record-set writes (PUT replaces, DELETE removes), so
// every write reads the zone and rewrites the affected sets, as libdns requires.
type goDaddyProvider struct {
	APIKey, APISecret string
	baseURL           string // overridden in tests
	client            *http.Client
}

const (
	goDaddyBase   = "https://api.godaddy.com"
	goDaddyMinTTL = 600
	goDaddyPage   = 500
)

// gdRecord is a record as the GoDaddy API represents it.
type gdRecord struct {
	Type     string `json:"type,omitempty"`
	Name     string `json:"name,omitempty"`
	Data     string `json:"data"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority,omitempty"`
	Weight   *int   `json:"weight,omitempty"`
	Port     *int   `json:"port,omitempty"`
	Service  string `json:"service,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// do sends one request. GoDaddy allows about 60 requests a minute and answers
// 429 beyond that, so a 429 is retried a few times after the wait it asks for.
func (g *goDaddyProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
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

func (g *goDaddyProvider) once(ctx context.Context, method, path string, payload []byte) (status int, out []byte, wait time.Duration, err error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	base := g.baseURL
	if base == "" {
		base = goDaddyBase
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return 0, nil, 0, err
	}
	req.Header.Set("Authorization", "sso-key "+g.APIKey+":"+g.APISecret)
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

func (g *goDaddyProvider) fail(what string, status int, body []byte) error {
	b := strings.TrimSpace(string(body))
	if len(b) > 300 {
		b = b[:300] + "..."
	}
	return fmt.Errorf("%s: GoDaddy answered %d: %s", what, status, b)
}

func gdDomain(zone string) string { return url.PathEscape(strings.TrimSuffix(zone, ".")) }

// list reads every record of the zone.
func (g *goDaddyProvider) list(ctx context.Context, zone string) ([]gdRecord, error) {
	var all []gdRecord
	for page := 1; ; page++ {
		status, body, err := g.do(ctx, http.MethodGet, fmt.Sprintf("/v1/domains/%s/records?offset=%d&limit=%d", gdDomain(zone), page, goDaddyPage), nil)
		if err != nil {
			return nil, err
		}
		if status == http.StatusUnprocessableEntity && page > 1 { // beyond the last page
			break
		}
		if status != http.StatusOK {
			return nil, g.fail("could not get records", status, body)
		}
		var recs []gdRecord
		if err := json.Unmarshal(body, &recs); err != nil {
			return nil, fmt.Errorf("could not decode GoDaddy's answer: %w", err)
		}
		all = append(all, recs...)
		if len(recs) < goDaddyPage {
			break
		}
	}
	return all, nil
}

func (g *goDaddyProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := g.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		out[i] = r.toLibdns()
	}
	return out, nil
}

// toLibdns renders the record in libdns' text form: MX is "priority target",
// SRV is "priority weight port target".
func (r gdRecord) toLibdns() libdns.Record {
	data := r.Data
	switch strings.ToUpper(r.Type) {
	case "MX":
		data = fmt.Sprintf("%d %s", deref(r.Priority), r.Data)
	case "SRV":
		data = fmt.Sprintf("%d %d %d %s", deref(r.Priority), deref(r.Weight), deref(r.Port), r.Data)
	}
	return libdns.RR{Name: r.Name, Type: strings.ToUpper(r.Type), TTL: time.Duration(r.TTL) * time.Second, Data: data}
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func gdInt(s string) (*int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("%q is not a valid number", s)
	}
	return &n, nil
}

// fromLibdns converts a record to the API form, raising the TTL to GoDaddy's
// minimum.
func gdFromLibdns(rec libdns.Record) (gdRecord, error) {
	rr := rec.RR()
	out := gdRecord{Type: strings.ToUpper(rr.Type), Name: gdName(rr.Name), Data: rr.Data, TTL: int(rr.TTL / time.Second)}
	if out.TTL < goDaddyMinTTL {
		out.TTL = goDaddyMinTTL
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
		labels := strings.Split(out.Name, ".")
		if len(labels) < 2 || !strings.HasPrefix(labels[0], "_") || !strings.HasPrefix(labels[1], "_") {
			return out, fmt.Errorf("SRV name must start with _service._protocol")
		}
		out.Service, out.Protocol = labels[0], labels[1]
	}
	return out, nil
}

func gdName(n string) string {
	if n == "" {
		return "@"
	}
	return n
}

type gdKey struct{ typ, name string }

func (r gdRecord) key() gdKey { return gdKey{strings.ToUpper(r.Type), strings.ToLower(gdName(r.Name))} }

// sameValue compares two records of one set by value, ignoring the TTL.
func (r gdRecord) sameValue(o gdRecord) bool {
	return strings.EqualFold(r.Data, o.Data) && deref(r.Priority) == deref(o.Priority) &&
		deref(r.Weight) == deref(o.Weight) && deref(r.Port) == deref(o.Port)
}

// put replaces the record set (typ, name) with recs, or removes the set when
// recs is empty.
func (g *goDaddyProvider) put(ctx context.Context, zone string, k gdKey, name string, recs []gdRecord) error {
	path := fmt.Sprintf("/v1/domains/%s/records/%s/%s", gdDomain(zone), k.typ, url.PathEscape(name))
	if len(recs) == 0 {
		status, body, err := g.do(ctx, http.MethodDelete, path, nil)
		if err != nil {
			return err
		}
		if status != http.StatusNoContent && status != http.StatusOK {
			return g.fail("could not delete "+k.typ+" records", status, body)
		}
		return nil
	}
	payload := make([]gdRecord, len(recs))
	for i, r := range recs {
		payload[i] = r
		payload[i].Type, payload[i].Name = "", "" // implied by the path
	}
	status, body, err := g.do(ctx, http.MethodPut, path, payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return g.fail("could not write "+k.typ+" records", status, body)
	}
	return nil
}

// group splits recs by record set, in a stable order.
func gdGroup(recs []gdRecord) (map[gdKey][]gdRecord, []gdKey) {
	m := map[gdKey][]gdRecord{}
	var order []gdKey
	for _, r := range recs {
		k := r.key()
		if _, ok := m[k]; !ok {
			order = append(order, k)
		}
		m[k] = append(m[k], r)
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].name != order[j].name {
			return order[i].name < order[j].name
		}
		return order[i].typ < order[j].typ
	})
	return m, order
}

func gdConvert(recs []libdns.Record) ([]gdRecord, error) {
	out := make([]gdRecord, len(recs))
	for i, r := range recs {
		var err error
		if out[i], err = gdFromLibdns(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func toLibdnsList(recs []gdRecord) []libdns.Record {
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		out[i] = r.toLibdns()
	}
	return out
}

// AppendRecords adds the records to their sets, keeping the ones already there.
func (g *goDaddyProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := gdConvert(recs)
	if err != nil {
		return nil, err
	}
	existing, err := g.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	have, _ := gdGroup(existing)
	add, order := gdGroup(in)
	for _, k := range order {
		merged := append([]gdRecord{}, have[k]...)
		for _, n := range add[k] {
			dup := false
			for _, e := range merged {
				dup = dup || e.sameValue(n)
			}
			if !dup {
				merged = append(merged, n)
			}
		}
		if err := g.put(ctx, zone, k, add[k][0].Name, merged); err != nil {
			return nil, err
		}
	}
	return toLibdnsList(in), nil
}

// SetRecords makes the given records the only members of their sets.
func (g *goDaddyProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := gdConvert(recs)
	if err != nil {
		return nil, err
	}
	set, order := gdGroup(in)
	for _, k := range order {
		if err := g.put(ctx, zone, k, set[k][0].Name, set[k]); err != nil {
			return nil, err
		}
	}
	return toLibdnsList(in), nil
}

// DeleteRecords removes the records that match by name and type and, when the
// input states them, by value and TTL. Other members of a set stay.
func (g *goDaddyProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	existing, err := g.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	have, _ := gdGroup(existing)
	var deleted []libdns.Record
	done := map[gdKey]bool{}
	for _, rec := range recs {
		rr := rec.RR()
		k := gdKey{strings.ToUpper(rr.Type), strings.ToLower(gdName(rr.Name))}
		if done[k] {
			continue
		}
		done[k] = true
		var want []libdns.RR
		for _, r := range recs {
			if x := r.RR(); strings.EqualFold(x.Type, rr.Type) && strings.EqualFold(gdName(x.Name), gdName(rr.Name)) {
				want = append(want, x)
			}
		}
		var keep, drop []gdRecord
		for _, e := range have[k] {
			match := false
			el := e.toLibdns().RR()
			for _, w := range want {
				if (w.Data == "" || strings.EqualFold(w.Data, el.Data)) && (w.TTL == 0 || w.TTL == el.TTL) {
					match = true
				}
			}
			if match {
				drop = append(drop, e)
			} else {
				keep = append(keep, e)
			}
		}
		if len(drop) == 0 {
			continue
		}
		if err := g.put(ctx, zone, k, drop[0].Name, keep); err != nil {
			return deleted, err
		}
		deleted = append(deleted, toLibdnsList(drop)...)
	}
	return deleted, nil
}
