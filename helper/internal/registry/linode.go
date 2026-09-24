package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// linodeProvider talks to the Linode (Akamai) API v4 itself. The libdns linode
// package (v0.5.0) reads SRV records with their name doubled: Linode returns
// the name "_sip._tcp" and the package also sets the service and protocol, so
// the record comes back as "_sip._tcp._sip._tcp", and deleting one by the name
// dnshelper shows never matches. Verified against the API (2026-09-24):
//
//   - an SRV record has no name of its own: it is written as service, protocol,
//     priority, weight, port and target (an explicit 0 is kept; they are
//     pointers here, see issue #19), and always sits directly under the zone,
//     "_service._protocol". A name below that is ignored by the API, so such a
//     record is refused here;
//   - targets may be sent with or without the final dot and are read back
//     without it; the zone apex is the empty name;
//   - TTLs are rounded up to the next value Linode allows (30, 120, 300, 3600,
//     ...); 0 means the zone's default and is read back as 0 (unspecified);
//   - CAA has no flags (always 0);
//   - the zone's own NS records are implicit and not listed;
//   - records are single objects with an ID, so appends and deletes touch only
//     the records named, never the rest of the set.
type linodeProvider struct {
	APIToken string
	baseURL  string // overridden in tests
	pageSize int    // items per request; 0 means the default, set in tests
	client   *http.Client
}

const (
	linodeBase = "https://api.linode.com"
	linodePage = 500
)

// lnRecord is a record as the Linode API represents it.
type lnRecord struct {
	ID       int     `json:"id,omitempty"`
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Target   string  `json:"target"`
	Priority *int    `json:"priority,omitempty"`
	Weight   *int    `json:"weight,omitempty"`
	Port     *int    `json:"port,omitempty"`
	Service  *string `json:"service,omitempty"`
	Protocol *string `json:"protocol,omitempty"`
	TTL      int     `json:"ttl_sec,omitempty"`
	Tag      *string `json:"tag,omitempty"`
}

// do sends one request, retrying a few times when Linode answers 429.
func (p *linodeProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		status, out, wait, err := p.once(ctx, method, path, payload)
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

func (p *linodeProvider) once(ctx context.Context, method, path string, payload []byte) (status int, out []byte, wait time.Duration, err error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	base := p.baseURL
	if base == "" {
		base = linodeBase
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return 0, nil, 0, err
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

// fail reports an unexpected answer with Linode's own reasons, which never
// contain the token.
func (p *linodeProvider) fail(what string, status int, body []byte) error {
	var e struct {
		Errors []struct {
			Field  string `json:"field"`
			Reason string `json:"reason"`
		} `json:"errors"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		var parts []string
		for _, x := range e.Errors {
			if x.Field != "" {
				parts = append(parts, x.Field+": "+x.Reason)
			} else {
				parts = append(parts, x.Reason)
			}
		}
		msg = strings.Join(parts, "; ")
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return fmt.Errorf("%s: Linode answered %d: %s", what, status, msg)
}

func (p *linodeProvider) page() int {
	if p.pageSize > 0 {
		return p.pageSize
	}
	return linodePage
}

type lnDomain struct {
	ID     int    `json:"id"`
	Domain string `json:"domain"`
	Type   string `json:"type"`
}

// getAll reads every page of a list endpoint into out, one page at a time.
func (p *linodeProvider) getAll(ctx context.Context, path, what string, each func(json.RawMessage) error) error {
	for n := 1; ; n++ {
		status, body, err := p.do(ctx, http.MethodGet, fmt.Sprintf("%s?page=%d&page_size=%d", path, n, p.page()), nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return &lnStatus{status, p.fail("could not "+what, status, body)}
		}
		var res struct {
			Data  []json.RawMessage `json:"data"`
			Pages int               `json:"pages"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return fmt.Errorf("could not decode Linode's answer: %w", err)
		}
		for _, d := range res.Data {
			if err := each(d); err != nil {
				return err
			}
		}
		if n >= res.Pages {
			return nil
		}
	}
}

// lnStatus keeps the HTTP status of a failed list, so callers can tell a
// missing zone or a forbidden list from other failures.
type lnStatus struct {
	status int
	err    error
}

func (e *lnStatus) Error() string { return e.err.Error() }

func (p *linodeProvider) domains(ctx context.Context) ([]lnDomain, error) {
	var out []lnDomain
	err := p.getAll(ctx, "/v4/domains", "list domains", func(m json.RawMessage) error {
		var d lnDomain
		if err := json.Unmarshal(m, &d); err != nil {
			return fmt.Errorf("could not decode Linode's answer: %w", err)
		}
		out = append(out, d)
		return nil
	})
	return out, err
}

// ListZones lists the account's master zones; slave zones are copies of a zone
// held elsewhere. A token without the Domains scope is refused the list.
func (p *linodeProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	ds, err := p.domains(ctx)
	if se, ok := err.(*lnStatus); ok && se.status == http.StatusForbidden {
		return nil, &contract.Error{Code: contract.CodeUnsupported, Message: "this Linode token is not allowed to list domains"}
	}
	if err != nil {
		return nil, err
	}
	var zones []libdns.Zone
	for _, d := range ds {
		if d.Type == "master" {
			zones = append(zones, libdns.Zone{Name: d.Domain + "."})
		}
	}
	return zones, nil
}

// domainID finds the zone's ID; the API addresses zones by ID only.
func (p *linodeProvider) domainID(ctx context.Context, zone string) (int, error) {
	ds, err := p.domains(ctx)
	if err != nil {
		return 0, err
	}
	name := strings.TrimSuffix(zone, ".")
	for _, d := range ds {
		if strings.EqualFold(d.Domain, name) {
			return d.ID, nil
		}
	}
	return 0, &contract.Error{Code: contract.CodeZoneNotFound, Message: "Linode does not have the domain " + name}
}

func lnRecordsPath(id int) string { return "/v4/domains/" + strconv.Itoa(id) + "/records" }

// list reads every record of the zone, and returns the zone's ID with them.
func (p *linodeProvider) list(ctx context.Context, zone string) (int, []lnRecord, error) {
	id, err := p.domainID(ctx, zone)
	if err != nil {
		return 0, nil, err
	}
	var all []lnRecord
	err = p.getAll(ctx, lnRecordsPath(id), "get records", func(m json.RawMessage) error {
		var r lnRecord
		if err := json.Unmarshal(m, &r); err != nil {
			return fmt.Errorf("could not decode Linode's answer: %w", err)
		}
		all = append(all, r)
		return nil
	})
	return id, all, err
}

func (p *linodeProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	_, recs, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		out[i] = r.toLibdns()
	}
	return out, nil
}

// lnHasTarget is the set of types whose target is a host name, read back
// without the final dot.
var lnHasTarget = map[string]bool{"CNAME": true, "MX": true, "NS": true, "SRV": true}

func lnDeref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// toLibdns renders the record in libdns' text form: MX is "priority target",
// SRV is "priority weight port target", CAA is `flags tag "value"`.
func (r lnRecord) toLibdns() libdns.Record {
	typ := strings.ToUpper(r.Type)
	data := r.Target
	if lnHasTarget[typ] && data != "" && !strings.HasSuffix(data, ".") {
		data += "."
	}
	switch typ {
	case "MX":
		data = fmt.Sprintf("%d %s", lnDeref(r.Priority), data)
	case "SRV":
		data = fmt.Sprintf("%d %d %d %s", lnDeref(r.Priority), lnDeref(r.Weight), lnDeref(r.Port), data)
	case "CAA":
		tag := ""
		if r.Tag != nil {
			tag = *r.Tag
		}
		data = fmt.Sprintf("0 %s %q", tag, r.Target)
	}
	return libdns.RR{Name: gdName(r.Name), Type: typ, TTL: time.Duration(r.TTL) * time.Second, Data: data}
}

func lnInt(n uint16) *int { v := int(n); return &v }

// lnFromLibdns converts a record to the API form. It refuses what Linode cannot
// store as asked, before anything is sent.
func lnFromLibdns(rec libdns.Record) (lnRecord, error) {
	rr := rec.RR()
	parsed, err := rr.Parse()
	if err != nil {
		return lnRecord{}, err
	}
	name := rr.Name
	if name == "@" {
		name = ""
	}
	out := lnRecord{Type: strings.ToUpper(rr.Type), Name: name, Target: rr.Data, TTL: int(rr.TTL / time.Second)}
	switch r := parsed.(type) {
	case libdns.MX:
		out.Priority, out.Target = lnInt(r.Preference), r.Target
	case libdns.SRV:
		if r.Name != "@" && r.Name != "" {
			return out, &contract.Error{Code: contract.CodeUnsupported,
				Message: fmt.Sprintf("Linode only stores SRV records directly under the zone (_service._protocol), not %q", rr.Name)}
		}
		svc, proto := r.Service, r.Transport
		out.Name = ""
		out.Service, out.Protocol = &svc, &proto
		out.Priority, out.Weight, out.Port, out.Target = lnInt(r.Priority), lnInt(r.Weight), lnInt(r.Port), r.Target
	case libdns.CAA:
		if r.Flags != 0 {
			return out, &contract.Error{Code: contract.CodeUnsupported, Message: "Linode does not support CAA flags"}
		}
		tag := r.Tag
		out.Tag, out.Target = &tag, r.Value
	case libdns.ServiceBinding:
		return out, &contract.Error{Code: contract.CodeUnsupported, Message: "Linode does not support " + out.Type + " records"}
	}
	return out, nil
}

// lnSame compares a record read from Linode with a wanted one: same name and,
// when want states them, the same type, value and TTL. Targets are compared
// without the final dot.
func lnSame(have, want libdns.RR) bool {
	return strings.EqualFold(gdName(have.Name), gdName(want.Name)) &&
		(want.Type == "" || strings.EqualFold(have.Type, want.Type)) &&
		(want.Data == "" || strings.EqualFold(strings.TrimSuffix(have.Data, "."), strings.TrimSuffix(want.Data, "."))) &&
		(want.TTL == 0 || want.TTL == have.TTL)
}

func (p *linodeProvider) create(ctx context.Context, id int, r lnRecord) (lnRecord, error) {
	status, body, err := p.do(ctx, http.MethodPost, lnRecordsPath(id), r)
	if err != nil {
		return r, err
	}
	if status != http.StatusOK {
		return r, p.fail("could not create a "+r.Type+" record", status, body)
	}
	var c lnRecord
	if err := json.Unmarshal(body, &c); err != nil {
		return r, fmt.Errorf("could not decode Linode's answer: %w", err)
	}
	return c, nil
}

func (p *linodeProvider) remove(ctx context.Context, id, rid int) error {
	status, body, err := p.do(ctx, http.MethodDelete, lnRecordsPath(id)+"/"+strconv.Itoa(rid), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNotFound {
		return p.fail("could not delete a record", status, body)
	}
	return nil
}

func lnConvert(recs []libdns.Record) ([]lnRecord, error) {
	out := make([]lnRecord, len(recs))
	for i, r := range recs {
		var err error
		if out[i], err = lnFromLibdns(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// AppendRecords creates the records and returns them as Linode stored them
// (TTL rounded up). It returns those created before an error.
func (p *linodeProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := lnConvert(recs)
	if err != nil {
		return nil, err
	}
	id, err := p.domainID(ctx, zone)
	if err != nil {
		return nil, err
	}
	var done []libdns.Record
	for _, r := range in {
		c, err := p.create(ctx, id, r)
		if err != nil {
			return done, err
		}
		done = append(done, c.toLibdns())
	}
	return done, nil
}

// DeleteRecords removes the records that match by name and, when the input
// states them, by type, value and TTL.
func (p *linodeProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	id, existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	var deleted []libdns.Record
	for _, e := range existing {
		have := e.toLibdns()
		for _, w := range recs {
			if lnSame(have.RR(), w.RR()) {
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
func (p *linodeProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in, err := lnConvert(recs)
	if err != nil {
		return nil, err
	}
	id, existing, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	want := make([]libdns.RR, len(recs))
	for i, r := range recs {
		want[i] = r.RR()
	}
	sameSet := func(a, b libdns.RR) bool {
		return strings.EqualFold(a.Type, b.Type) && strings.EqualFold(gdName(a.Name), gdName(b.Name))
	}
	kept := make([]bool, len(in))
	for _, e := range existing {
		have := e.toLibdns().RR()
		inSet, keep := false, false
		for i, w := range want {
			if !sameSet(have, w) {
				continue
			}
			inSet = true
			if !kept[i] && lnSame(have, w) {
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
	out := make([]libdns.Record, 0, len(in))
	for i, r := range in {
		if kept[i] {
			out = append(out, recs[i])
			continue
		}
		c, err := p.create(ctx, id, r)
		if err != nil {
			return nil, err
		}
		out = append(out, c.toLibdns())
	}
	return out, nil
}
