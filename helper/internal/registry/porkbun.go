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

// porkbunProvider talks to the Porkbun API (v3) itself. The libdns porkbun
// package (v1.1.0) cannot be used: its delete removes every record with the
// name and type whatever the value, it never sends an MX or SRV priority, it
// drops MX and NS records when reading and misnames SRV records, and it has no
// timeout. Verified against the API (2026-09-24):
//
//   - every call is a POST carrying the key and secret in the JSON body;
//   - MX and SRV take the priority as a separate "prio" field, sent here as a
//     string so an explicit "0" is always present (issue #19); an SRV's
//     content is "weight port target";
//   - names are returned fully qualified; targets are stored as sent, with or
//     without the final dot;
//   - a TTL under 60 is raised to 60; the default is 600;
//   - TXT values are served through Cloudflare, which drops a backslash (the
//     API still returns it), so backslashes are refused; double quotes and
//     long values are served correctly;
//   - with API access switched on for the account, a key could read and
//     write a domain whose own API access switch was off (listAll says
//     apiAccess 0), so that switch is not checked here;
//   - records have IDs, so appends and deletes touch only the records named.
type porkbunProvider struct {
	APIKey, SecretKey string
	baseURL           string // overridden in tests
	client            *http.Client
}

const porkbunBase = "https://api.porkbun.com/api/json/v3"

// pbRecord is a record as the Porkbun API represents it.
type pbRecord struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     pbStr  `json:"ttl,omitempty"`
	Prio    pbStr  `json:"prio,omitempty"`
}

// pbStr reads a field Porkbun sends as a string, a number or null.
type pbStr string

func (s *pbStr) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		*s = pbStr(x)
	case float64:
		*s = pbStr(strconv.FormatFloat(x, 'f', -1, 64))
	default:
		*s = ""
	}
	return nil
}

// pbAnswer is the envelope of every Porkbun answer.
type pbAnswer struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// call posts body (plus the credentials) to path and decodes the answer into
// out. Porkbun limits request rates, so 429 and 503 are retried a few times.
func (p *porkbunProvider) call(ctx context.Context, path string, body map[string]any, out any) error {
	if body == nil {
		body = map[string]any{}
	}
	body["apikey"], body["secretapikey"] = p.APIKey, p.SecretKey
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		status, raw, err := p.once(ctx, path, payload)
		if err != nil {
			return err
		}
		if (status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable) && attempt < 4 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}
		var a pbAnswer
		_ = json.Unmarshal(raw, &a)
		if status != http.StatusOK || a.Status != "SUCCESS" {
			return p.fail(status, a, raw)
		}
		if out != nil {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("could not decode Porkbun's answer: %w", err)
			}
		}
		return nil
	}
}

func (p *porkbunProvider) once(ctx context.Context, path string, payload []byte) (int, []byte, error) {
	base := p.baseURL
	if base == "" {
		base = porkbunBase
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
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

// fail turns an error answer into a structured error where the code says
// what happened. Porkbun's messages never contain the key or secret.
func (p *porkbunProvider) fail(status int, a pbAnswer, raw []byte) error {
	msg := a.Message
	if msg == "" {
		msg = strings.TrimSpace(string(raw))
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	switch {
	case strings.HasPrefix(a.Code, "INVALID_API_KEYS"):
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "Porkbun rejected the API key or secret"}
	case a.Code == "INVALID_DOMAIN":
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "Porkbun does not have this domain in the account"}
	}
	return fmt.Errorf("Porkbun answered %d: %s", status, msg)
}

func pbDomain(zone string) string { return url.PathEscape(strings.TrimSuffix(zone, ".")) }

// ListZones lists the domains of the account, 1000 at a time.
func (p *porkbunProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	var zones []libdns.Zone
	for start := 0; ; start += 1000 {
		var res struct {
			Domains []struct {
				Domain string `json:"domain"`
			} `json:"domains"`
		}
		if err := p.call(ctx, "/domain/listAll", map[string]any{"start": strconv.Itoa(start)}, &res); err != nil {
			return nil, err
		}
		for _, d := range res.Domains {
			zones = append(zones, libdns.Zone{Name: d.Domain + "."})
		}
		if len(res.Domains) < 1000 {
			return zones, nil
		}
	}
}

func (p *porkbunProvider) list(ctx context.Context, zone string) ([]pbRecord, error) {
	var res struct {
		Records []pbRecord `json:"records"`
	}
	if err := p.call(ctx, "/dns/retrieve/"+pbDomain(zone), nil, &res); err != nil {
		return nil, err
	}
	return res.Records, nil
}

func (p *porkbunProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		out[i] = r.toLibdns(zone)
	}
	return out, nil
}

// pbHasTarget is the set of types whose content ends in a host name, which
// Porkbun stores as sent and which is read back fully qualified.
var pbHasTarget = map[string]bool{"ALIAS": true, "CNAME": true, "MX": true, "NS": true, "SRV": true}

func pbFQDN(s string) string {
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// toLibdns renders the record in libdns' text form: MX is "priority target",
// SRV is "priority weight port target".
func (r pbRecord) toLibdns(zone string) libdns.Record {
	typ := strings.ToUpper(r.Type)
	data := r.Content
	if pbHasTarget[typ] {
		if f := strings.Fields(data); len(f) > 0 {
			f[len(f)-1] = pbFQDN(f[len(f)-1])
			data = strings.Join(f, " ")
		}
	}
	prio := string(r.Prio)
	if prio == "" {
		prio = "0"
	}
	switch typ {
	case "MX", "SRV":
		data = prio + " " + data
	}
	ttl, _ := strconv.Atoi(string(r.TTL))
	return libdns.RR{Name: libdns.RelativeName(pbFQDN(r.Name), pbFQDN(zone)), Type: typ, TTL: time.Duration(ttl) * time.Second, Data: data}
}

// pbFromLibdns converts a record to the API form.
func pbFromLibdns(rec libdns.Record) (pbRecord, error) {
	rr := rec.RR()
	name := rr.Name
	if name == "@" {
		name = ""
	}
	out := pbRecord{Name: name, Type: strings.ToUpper(rr.Type), Content: rr.Data}
	if ttl := int(rr.TTL / time.Second); ttl > 0 {
		out.TTL = pbStr(strconv.Itoa(ttl))
	}
	f := strings.Fields(rr.Data)
	switch out.Type {
	case "MX":
		if len(f) != 2 {
			return out, fmt.Errorf("MX data must be \"priority target\"")
		}
		if _, err := gdInt(f[0]); err != nil {
			return out, err
		}
		out.Prio, out.Content = pbStr(f[0]), f[1]
	case "SRV":
		if len(f) != 4 {
			return out, fmt.Errorf("SRV data must be \"priority weight port target\"")
		}
		for _, n := range f[:3] {
			if _, err := gdInt(n); err != nil {
				return out, err
			}
		}
		out.Prio, out.Content = pbStr(f[0]), strings.Join(f[1:], " ")
	}
	return out, nil
}

func (p *porkbunProvider) create(ctx context.Context, zone string, r pbRecord) error {
	// The priority goes in as its own key whenever the type has one, so a
	// priority of "0" is always sent, never left out.
	body := map[string]any{"name": r.Name, "type": r.Type, "content": r.Content}
	if r.TTL != "" {
		body["ttl"] = string(r.TTL)
	}
	if r.Type == "MX" || r.Type == "SRV" {
		body["prio"] = string(r.Prio)
	}
	return p.call(ctx, "/dns/create/"+pbDomain(zone), body, nil)
}

func pbConvert(recs []libdns.Record) ([]pbRecord, error) {
	out := make([]pbRecord, len(recs))
	for i, r := range recs {
		var err error
		if out[i], err = pbFromLibdns(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// AppendRecords creates the records. It returns those created before an error.
func (p *porkbunProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := pbConvert(recs)
	if err != nil {
		return nil, err
	}
	var done []libdns.Record
	for i, r := range in {
		if err := p.create(ctx, zone, r); err != nil {
			return done, err
		}
		done = append(done, recs[i])
	}
	return done, nil
}

// pbSame compares a record read from Porkbun with a wanted one: same name and,
// when want states them, the same type, value and TTL. Targets are compared
// without the final dot.
func pbSame(have, want libdns.RR) bool {
	return strings.EqualFold(gdName(have.Name), gdName(want.Name)) &&
		(want.Type == "" || strings.EqualFold(have.Type, want.Type)) &&
		(want.Data == "" || strings.EqualFold(strings.TrimSuffix(have.Data, "."), strings.TrimSuffix(want.Data, "."))) &&
		(want.TTL == 0 || want.TTL == have.TTL)
}

func (p *porkbunProvider) remove(ctx context.Context, zone, id string) error {
	return p.call(ctx, "/dns/delete/"+pbDomain(zone)+"/"+url.PathEscape(id), nil, nil)
}

// DeleteRecords removes the records that match by name and, when the input
// states them, by type, value and TTL.
func (p *porkbunProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	var deleted []libdns.Record
	for _, e := range existing {
		have := e.toLibdns(zone)
		for _, w := range recs {
			if pbSame(have.RR(), w.RR()) {
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
func (p *porkbunProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := pbConvert(recs)
	if err != nil {
		return nil, err
	}
	existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	kept := make([]bool, len(in))
	for _, e := range existing {
		have := e.toLibdns(zone).RR()
		inSet, keep := false, false
		for i, r := range recs {
			w := r.RR()
			if !strings.EqualFold(have.Type, w.Type) || !strings.EqualFold(gdName(have.Name), gdName(w.Name)) {
				continue
			}
			inSet = true
			if !kept[i] && pbSame(have, w) {
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
			if err := p.create(ctx, zone, r); err != nil {
				return nil, err
			}
		}
	}
	return recs, nil
}
