package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// ionosProvider talks to the IONOS DNS API (v1) itself. The libdns ionos
// package (v1.2.0) is built on a pre-release libdns API (v1.0.0-beta.1) and
// sends TXT values as plain text, which IONOS mangles (see below). Verified
// against the API (2026-09-25):
//
//   - the key is sent as "X-API-Key: prefix.secret"; a wrong one gets 401;
//     so does a zone id the account does not have, so zones are looked up by
//     name in the zone list;
//   - records have IDs; several can be created in one POST, and each is
//     deleted on its own;
//   - names are fully qualified, stored in lower case; MX and SRV take the
//     priority in a separate "prio" field, which IONOS requires for them: it
//     is always sent, 0 included (issue #19); an SRV's content is
//     "weight port target"; targets are stored without the final dot;
//   - a TXT value sent as plain text is quoted by IONOS, but a double quote
//     inside it becomes a string boundary and non-ASCII letters lose their
//     accents (é becomes e). Sent already quoted and escaped (with \DDD for
//     non-ASCII bytes), it is stored and served as sent;
//   - the TTL must be at least 60; without one a record gets 3600;
//   - disabled records are read but not served; they are left alone.
type ionosProvider struct {
	Prefix, Secret string
	baseURL        string // overridden in tests
	client         *http.Client
	zoneIDs        map[string]string // zone name -> id
}

const (
	ionosBase   = "https://api.hosting.ionos.com/dns/v1"
	ionosMinTTL = 60
)

// ioRecord is a record as the IONOS API represents it.
type ioRecord struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl,omitempty"`
	Prio     *int   `json:"prio,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
}

// do sends one request. A 429 is retried a few times after the wait IONOS
// asks for.
func (p *ionosProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	base := p.baseURL
	if base == "" {
		base = ionosBase
	}
	c := p.client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("X-API-Key", p.Prefix+"."+p.Secret)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		out, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests || attempt >= 4 || err != nil {
			return resp.StatusCode, out, err
		}
		wait := 2 * time.Second
		if n, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && n > 0 && n <= 60 {
			wait = time.Duration(n) * time.Second
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// fail turns an error answer into a structured error. IONOS answers either
// {"message": ...} or a list of {"code", "message", "parameters"}; neither
// contains the key.
func (p *ionosProvider) fail(what string, status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	var one struct {
		Message string `json:"message"`
	}
	var many []struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		Parameters struct {
			InvalidFields  []string `json:"invalidFields"`
			RequiredFields []string `json:"requiredFields"`
		} `json:"parameters"`
	}
	if json.Unmarshal(body, &one) == nil && one.Message != "" {
		msg = one.Message
	} else if json.Unmarshal(body, &many) == nil && len(many) > 0 {
		var parts []string
		for _, e := range many {
			s := e.Message
			if f := append(e.Parameters.InvalidFields, e.Parameters.RequiredFields...); len(f) > 0 {
				s += " (" + strings.Join(f, ", ") + ")"
			}
			parts = append(parts, s)
		}
		msg = strings.Join(parts, "; ")
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "IONOS refused the request (" + msg + "); check the key's prefix and secret"}
	case http.StatusNotFound:
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "IONOS has no such zone (" + msg + ")"}
	}
	return fmt.Errorf("%s: IONOS answered %d: %s", what, status, msg)
}

// zones reads the account's zones: name -> id.
func (p *ionosProvider) zones(ctx context.Context) (map[string]string, error) {
	if p.zoneIDs != nil {
		return p.zoneIDs, nil
	}
	status, body, err := p.do(ctx, http.MethodGet, "/zones", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, p.fail("could not list zones", status, body)
	}
	var zs []struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &zs); err != nil {
		return nil, fmt.Errorf("could not decode IONOS's answer: %w", err)
	}
	p.zoneIDs = map[string]string{}
	for _, z := range zs {
		if z.Type == "" || strings.EqualFold(z.Type, "NATIVE") {
			p.zoneIDs[strings.ToLower(strings.TrimSuffix(z.Name, "."))] = z.ID
		}
	}
	return p.zoneIDs, nil
}

func (p *ionosProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	zs, err := p.zones(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Zone, 0, len(zs))
	for name := range zs {
		out = append(out, libdns.Zone{Name: name + "."})
	}
	return out, nil
}

func (p *ionosProvider) zoneID(ctx context.Context, zone string) (string, error) {
	zs, err := p.zones(ctx)
	if err != nil {
		return "", err
	}
	id, ok := zs[strings.ToLower(strings.TrimSuffix(zone, "."))]
	if !ok {
		return "", &contract.Error{Code: contract.CodeZoneNotFound, Message: "the IONOS account has no zone " + strings.TrimSuffix(zone, ".")}
	}
	return id, nil
}

// list reads the zone's enabled records; disabled ones are left alone.
func (p *ionosProvider) list(ctx context.Context, zone string) (string, []ioRecord, error) {
	id, err := p.zoneID(ctx, zone)
	if err != nil {
		return "", nil, err
	}
	status, body, err := p.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(id), nil)
	if err != nil {
		return "", nil, err
	}
	if status != http.StatusOK {
		return "", nil, p.fail("could not get records", status, body)
	}
	var z struct {
		Records []ioRecord `json:"records"`
	}
	if err := json.Unmarshal(body, &z); err != nil {
		return "", nil, fmt.Errorf("could not decode IONOS's answer: %w", err)
	}
	var out []ioRecord
	for _, r := range z.Records {
		if !r.Disabled {
			out = append(out, r)
		}
	}
	return id, out, nil
}

func (p *ionosProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	_, recs, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		out[i] = r.toLibdns(zone)
	}
	return out, nil
}

// toLibdns renders the record in libdns' text form: MX is "priority target",
// SRV is "priority weight port target", TXT unquoted, targets with a final
// dot.
func (r ioRecord) toLibdns(zone string) libdns.RR {
	typ := strings.ToUpper(r.Type)
	data := r.Content
	switch {
	case typ == "A" || typ == "AAAA":
		// IONOS writes IPv6 addresses in full (2001:db8:0:0:0:0:0:1).
		if a, err := netip.ParseAddr(data); err == nil {
			data = a.String()
		}
	case isTXT(typ):
		data = txtUnquote(data)
	case hasTarget[typ]:
		if f := strings.Fields(data); len(f) > 0 {
			f[len(f)-1] = pbFQDN(f[len(f)-1])
			data = strings.Join(f, " ")
		}
	}
	if typ == "MX" || typ == "SRV" {
		prio := 0
		if r.Prio != nil {
			prio = *r.Prio
		}
		data = strconv.Itoa(prio) + " " + data
	}
	return libdns.RR{Name: libdns.RelativeName(pbFQDN(r.Name), pdZone(zone)), Type: typ, TTL: time.Duration(r.TTL) * time.Second, Data: data}
}

// ioFromLibdns converts a record to the API form.
func ioFromLibdns(zone string, rec libdns.Record) (ioRecord, error) {
	rr := rec.RR()
	out := ioRecord{
		Name: strings.TrimSuffix(strings.ToLower(libdns.AbsoluteName(gdName(rr.Name), pdZone(zone))), "."),
		Type: strings.ToUpper(rr.Type), Content: rr.Data, TTL: int(rr.TTL / time.Second),
	}
	if out.TTL > 0 && out.TTL < ionosMinTTL {
		out.TTL = ionosMinTTL
	}
	f := strings.Fields(rr.Data)
	switch out.Type {
	case "TXT", "SPF":
		out.Content = escapeNonASCII(txtQuote(rr.Data))
	case "MX":
		if len(f) != 2 {
			return out, fmt.Errorf("MX data must be \"priority target\"")
		}
		prio, err := gdInt(f[0])
		if err != nil {
			return out, err
		}
		out.Prio, out.Content = prio, f[1]
	case "SRV":
		if len(f) != 4 {
			return out, fmt.Errorf("SRV data must be \"priority weight port target\"")
		}
		for _, n := range f[:3] {
			if _, err := gdInt(n); err != nil {
				return out, err
			}
		}
		prio, _ := gdInt(f[0])
		out.Prio, out.Content = prio, strings.Join(f[1:], " ")
	}
	if hasTarget[out.Type] {
		if g := strings.Fields(out.Content); len(g) > 0 {
			g[len(g)-1] = pbFQDN(g[len(g)-1])
			out.Content = strings.Join(g, " ")
		}
	}
	return out, nil
}

func ioConvert(zone string, recs []libdns.Record) ([]ioRecord, error) {
	out := make([]ioRecord, len(recs))
	for i, r := range recs {
		var err error
		if out[i], err = ioFromLibdns(zone, r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// create adds the records in one request.
func (p *ionosProvider) create(ctx context.Context, zoneID string, recs []ioRecord) ([]ioRecord, error) {
	if len(recs) == 0 {
		return nil, nil
	}
	status, body, err := p.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/records", recs)
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, p.fail("could not create records", status, body)
	}
	var out []ioRecord
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("could not decode IONOS's answer: %w", err)
	}
	return out, nil
}

func (p *ionosProvider) remove(ctx context.Context, zoneID, id string) error {
	status, body, err := p.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/records/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return p.fail("could not delete a record", status, body)
	}
	return nil
}

// AppendRecords creates the records, all in one request.
func (p *ionosProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := ioConvert(zone, recs)
	if err != nil {
		return nil, err
	}
	id, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	made, err := p.create(ctx, id, in)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, len(made))
	for i, r := range made {
		out[i] = r.toLibdns(zone)
	}
	return out, nil
}

// DeleteRecords removes the records that match by name and, when the input
// states them, by type, value and TTL.
func (p *ionosProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	id, existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	var deleted []libdns.Record
	for _, e := range existing {
		have := e.toLibdns(zone)
		for _, w := range recs {
			if vuSame(have, w.RR()) {
				if err := p.remove(ctx, id, e.ID); err != nil {
					return deleted, err
				}
				deleted = append(deleted, have)
				break
			}
		}
	}
	return deleted, nil
}

// SetRecords makes the given records the only members of their sets: members
// with another value are deleted, missing ones created, equal ones left alone.
func (p *ionosProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := ioConvert(zone, recs)
	if err != nil {
		return nil, err
	}
	id, existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	kept := make([]bool, len(in))
	for _, e := range existing {
		have := e.toLibdns(zone)
		inSet, keep := false, false
		for i, r := range recs {
			w := r.RR()
			if !strings.EqualFold(have.Type, w.Type) || !strings.EqualFold(gdName(have.Name), gdName(w.Name)) {
				continue
			}
			inSet = true
			if !kept[i] && vuSame(have, w) {
				kept[i], keep = true, true
				break
			}
		}
		if inSet && !keep {
			if err := p.remove(ctx, id, e.ID); err != nil {
				return nil, err
			}
		}
	}
	var missing []ioRecord
	for i, r := range in {
		if !kept[i] {
			missing = append(missing, r)
		}
	}
	if _, err := p.create(ctx, id, missing); err != nil {
		return nil, err
	}
	return recs, nil
}
