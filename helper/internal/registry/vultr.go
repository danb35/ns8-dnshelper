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

// vultrProvider talks to the Vultr API (v2) itself. The libdns vultr package
// (v2.0.4) cannot be used: to delete a record it has no ID for, it picks the
// last record with the same name whatever its type or value, and its
// SetRecords updates the last record with the same value instead of replacing
// the set. Verified against the API (2026-09-25):
//
//   - the token is sent as a Bearer token; a wrong one gets 401;
//   - records have IDs, so appends and deletes touch only the records named;
//   - MX and SRV take the priority as a separate field, which the API
//     requires; it is always sent, 0 included (issue #19); an SRV's data is
//     "weight port target"; other types read back priority -1;
//   - names are stored in lower case, "" for the apex; MX and CNAME targets
//     are stored without the final dot, SRV targets as sent;
//   - TXT values are sent unquoted and read back quoted; the name servers
//     split long ones into 255-byte strings. The API refuses a double quote
//     inside the value and keeps a backslash that the name servers then drop,
//     so both are refused (TXTForbidden);
//   - a TTL under 60 is raised to 60; without one a record gets 300;
//   - an unknown domain gets 404; lists are paged with a cursor.
type vultrProvider struct {
	APIToken string
	baseURL  string // overridden in tests
	perPage  int    // 0 means vultrPage, set in tests
	client   *http.Client
}

const (
	vultrBase   = "https://api.vultr.com/v2"
	vultrMinTTL = 60
	vultrPage   = 500
)

// vuRecord is a record as the Vultr API represents it.
type vuRecord struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Data     string `json:"data"`
	Priority *int   `json:"priority,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
}

// do sends one request. Vultr allows 30 requests a second and answers 429
// beyond that, so a 429 is retried a few times.
func (p *vultrProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
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
		case <-time.After(time.Second):
		}
	}
}

func (p *vultrProvider) once(ctx context.Context, method, path string, payload []byte) (int, []byte, error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	base := p.baseURL
	if base == "" {
		base = vultrBase
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

// fail turns an error answer into a structured error where the status says
// what happened. Vultr's messages never contain the token.
func (p *vultrProvider) fail(what string, status int, body []byte) error {
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "Vultr refused the request (" + msg + "); check the token and the API access control list"}
	case http.StatusNotFound:
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "Vultr has no such domain in this account"}
	}
	return fmt.Errorf("%s: Vultr answered %d: %s", what, status, msg)
}

func vuDomain(zone string) string { return url.PathEscape(strings.TrimSuffix(zone, ".")) }

// pages reads every page of a list; Vultr gives the next page's cursor in
// meta.links.next.
func (p *vultrProvider) pages(ctx context.Context, what, path string, each func([]byte) error) error {
	size := p.perPage
	if size == 0 {
		size = vultrPage
	}
	cursor := ""
	for {
		q := path + "?per_page=" + strconv.Itoa(size)
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		status, body, err := p.do(ctx, http.MethodGet, q, nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return p.fail(what, status, body)
		}
		var meta struct {
			Meta struct {
				Links struct {
					Next string `json:"next"`
				} `json:"links"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &meta); err != nil {
			return fmt.Errorf("could not decode Vultr's answer: %w", err)
		}
		if err := each(body); err != nil {
			return fmt.Errorf("could not decode Vultr's answer: %w", err)
		}
		if meta.Meta.Links.Next == "" || meta.Meta.Links.Next == cursor {
			return nil
		}
		cursor = meta.Meta.Links.Next
	}
}

// ListZones lists the domains of the account.
func (p *vultrProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	var zones []libdns.Zone
	err := p.pages(ctx, "could not list domains", "/domains", func(b []byte) error {
		var res struct {
			Domains []struct {
				Domain string `json:"domain"`
			} `json:"domains"`
		}
		if err := json.Unmarshal(b, &res); err != nil {
			return err
		}
		for _, d := range res.Domains {
			zones = append(zones, libdns.Zone{Name: d.Domain + "."})
		}
		return nil
	})
	return zones, err
}

func (p *vultrProvider) list(ctx context.Context, zone string) ([]vuRecord, error) {
	var all []vuRecord
	err := p.pages(ctx, "could not get records", "/domains/"+vuDomain(zone)+"/records", func(b []byte) error {
		var res struct {
			Records []vuRecord `json:"records"`
		}
		if err := json.Unmarshal(b, &res); err != nil {
			return err
		}
		all = append(all, res.Records...)
		return nil
	})
	return all, err
}

func (p *vultrProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := p.list(ctx, zone)
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
// SRV is "priority weight port target", TXT unquoted, targets with a final
// dot.
func (r vuRecord) toLibdns() libdns.RR {
	typ := strings.ToUpper(r.Type)
	data := r.Data
	switch {
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
		if r.Priority != nil && *r.Priority > 0 {
			prio = *r.Priority
		}
		data = strconv.Itoa(prio) + " " + data
	}
	return libdns.RR{Name: gdName(r.Name), Type: typ, TTL: time.Duration(r.TTL) * time.Second, Data: data}
}

// vuFromLibdns converts a record to the API form. The priority of MX and SRV
// goes in its own field, always present.
func vuFromLibdns(rec libdns.Record) (vuRecord, error) {
	rr := rec.RR()
	name := strings.ToLower(rr.Name)
	if name == "@" {
		name = ""
	}
	out := vuRecord{Type: strings.ToUpper(rr.Type), Name: name, Data: rr.Data, TTL: int(rr.TTL / time.Second)}
	if out.TTL > 0 && out.TTL < vultrMinTTL {
		out.TTL = vultrMinTTL
	}
	f := strings.Fields(rr.Data)
	switch out.Type {
	case "MX":
		if len(f) != 2 {
			return out, fmt.Errorf("MX data must be \"priority target\"")
		}
		prio, err := gdInt(f[0])
		if err != nil {
			return out, err
		}
		out.Priority, out.Data = prio, f[1]
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
		out.Priority, out.Data = prio, strings.Join(f[1:], " ")
	}
	if hasTarget[out.Type] {
		if g := strings.Fields(out.Data); len(g) > 0 {
			g[len(g)-1] = pbFQDN(g[len(g)-1])
			out.Data = strings.Join(g, " ")
		}
	}
	return out, nil
}

// vuSame reports whether the record read from Vultr is what want describes:
// same name and, when want states them, the same type, value and TTL.
func vuSame(have, want libdns.RR) bool {
	return strings.EqualFold(gdName(have.Name), gdName(want.Name)) &&
		(want.Type == "" || strings.EqualFold(have.Type, want.Type)) &&
		(want.Data == "" || sameRData(have.Type, have.Data, want.Data)) &&
		(want.TTL == 0 || want.TTL == have.TTL)
}

func (p *vultrProvider) create(ctx context.Context, zone string, r vuRecord) (vuRecord, error) {
	status, body, err := p.do(ctx, http.MethodPost, "/domains/"+vuDomain(zone)+"/records", r)
	if err != nil {
		return r, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return r, p.fail("could not create a "+r.Type+" record", status, body)
	}
	var res struct {
		Record vuRecord `json:"record"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return r, fmt.Errorf("could not decode Vultr's answer: %w", err)
	}
	return res.Record, nil
}

func (p *vultrProvider) remove(ctx context.Context, zone, id string) error {
	status, body, err := p.do(ctx, http.MethodDelete, "/domains/"+vuDomain(zone)+"/records/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK && status != http.StatusNotFound {
		return p.fail("could not delete a record", status, body)
	}
	return nil
}

func vuConvert(recs []libdns.Record) ([]vuRecord, error) {
	out := make([]vuRecord, len(recs))
	for i, r := range recs {
		var err error
		if out[i], err = vuFromLibdns(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// AppendRecords creates the records. It returns those created before an error.
func (p *vultrProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := vuConvert(recs)
	if err != nil {
		return nil, err
	}
	var done []libdns.Record
	for _, r := range in {
		c, err := p.create(ctx, zone, r)
		if err != nil {
			return done, err
		}
		done = append(done, c.toLibdns())
	}
	return done, nil
}

// DeleteRecords removes the records that match by name and, when the input
// states them, by type, value and TTL.
func (p *vultrProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	var deleted []libdns.Record
	for _, e := range existing {
		have := e.toLibdns()
		for _, w := range recs {
			if vuSame(have, w.RR()) {
				if err := p.remove(ctx, zone, e.ID); err != nil {
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
func (p *vultrProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := vuConvert(recs)
	if err != nil {
		return nil, err
	}
	existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	kept := make([]bool, len(in))
	for _, e := range existing {
		have := e.toLibdns()
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
			if err := p.remove(ctx, zone, e.ID); err != nil {
				return nil, err
			}
		}
	}
	for i, r := range in {
		if !kept[i] {
			if _, err := p.create(ctx, zone, r); err != nil {
				return nil, err
			}
		}
	}
	return recs, nil
}
