package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// desecProvider talks to the deSEC API (v1) itself. The libdns desec package
// (v1.1.1) is close but cannot be used as it is: it reads a TXT value that
// deSEC has split into several strings (every value over 255 bytes, such as a
// DKIM key) with a stray `" "` inside, it prints to stdout when a value does
// not parse (stdout carries the helper's answer), it deletes only values
// written exactly as it would write them (deSEC rewrites 2001:DB8:0::1 as
// 2001:db8::1), it assumes a minimum TTL of 3600 where each domain has its
// own, and it fails on zones with more than 500 record sets. Verified against
// the API (2026-09-25):
//
//   - the token is sent as "Authorization: Token ..."; a wrong one gets 401;
//     a token needs no permission to create or delete domains;
//   - deSEC stores record sets: a bulk PUT to /domains/{name}/rrsets/
//     replaces the sets it names and leaves the others alone, all or nothing;
//     a set written with no records is removed. The apex is subname "";
//   - every write needs a TTL, at least the domain's minimum_ttl (900 for
//     the test domain);
//   - subnames must be lower case; targets must end in a dot; TXT values must
//     be quoted, and a string over 255 bytes is split by deSEC;
//   - every value is one presentation-format string, SRV "0 0 443 target."
//     included, so the zero-value bug of issue #19 cannot occur;
//   - writes are limited to 2/s, 15/min, 100/h and 300/day per domain, and
//     reads to 10/s and 50/min per account, so every change is one bulk
//     request, and 429 answers are retried after the time they give.
type desecProvider struct {
	Token   string
	baseURL string // overridden in tests
	client  *http.Client
}

const (
	desecBase       = "https://desec.io/api/v1"
	desecDefaultTTL = 3600
	desecMaxTTL     = 86400
	// desecMaxWait is the longest wait for the rate limit before giving up
	// with an error that says how long to wait.
	desecMaxWait = 90 * time.Second
)

// dsRRset is a record set as the deSEC API represents it.
type dsRRset struct {
	Subname string   `json:"subname"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

func (p *desecProvider) do(ctx context.Context, method, path string, body any) (int, http.Header, []byte, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, nil, nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		status, hdr, out, err := p.once(ctx, method, path, payload)
		if err != nil || status != http.StatusTooManyRequests {
			return status, hdr, out, err
		}
		wait := time.Second
		if n, e := strconv.Atoi(hdr.Get("Retry-After")); e == nil && n > 0 {
			wait = time.Duration(n) * time.Second
		}
		deadline, ok := ctx.Deadline()
		if wait > desecMaxWait || attempt >= 8 || (ok && time.Until(deadline) < wait) {
			return 0, nil, nil, fmt.Errorf("deSEC's rate limit is reached; try again in %d seconds", int(wait/time.Second))
		}
		select {
		case <-ctx.Done():
			return 0, nil, nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (p *desecProvider) once(ctx context.Context, method, path string, payload []byte) (int, http.Header, []byte, error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base()+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Token "+p.Token)
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
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, resp.Header, out, err
}

// fail turns an error answer into a structured error where the status says
// what happened. deSEC's messages never contain the token.
func (p *desecProvider) fail(what string, status int, body []byte) error {
	switch status {
	case http.StatusUnauthorized:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "deSEC rejected the token"}
	case http.StatusForbidden:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "deSEC does not allow this token to do that; check the token's scope and policies"}
	case http.StatusNotFound:
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "deSEC has no such domain in this account"}
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return fmt.Errorf("%s: deSEC answered %d: %s", what, status, msg)
}

func (p *desecProvider) base() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return desecBase
}

func dsDomain(zone string) string { return url.PathEscape(strings.TrimSuffix(zone, ".")) }

var dsNextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// pages reads a list that deSEC pages with a cursor once it is long; an empty
// cursor asks for the first page.
func (p *desecProvider) pages(ctx context.Context, what, path string, each func([]byte) error) error {
	next := path + "?cursor="
	for next != "" {
		status, hdr, body, err := p.do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return p.fail(what, status, body)
		}
		if err := each(body); err != nil {
			return fmt.Errorf("could not decode deSEC's answer: %w", err)
		}
		next = ""
		if m := dsNextLink.FindStringSubmatch(hdr.Get("Link")); m != nil {
			// Only follow links on the API itself, so the token goes nowhere else.
			rest, ok := strings.CutPrefix(m[1], p.base()+"/")
			if !ok {
				return fmt.Errorf("%s: deSEC gave an unexpected next page %q", what, m[1])
			}
			next = "/" + rest
		}
	}
	return nil
}

// ListZones lists the domains of the account.
func (p *desecProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	var zones []libdns.Zone
	err := p.pages(ctx, "could not list domains", "/domains/", func(b []byte) error {
		var page []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		for _, d := range page {
			zones = append(zones, libdns.Zone{Name: d.Name + "."})
		}
		return nil
	})
	return zones, err
}

// minTTL reads the domain's minimum TTL.
func (p *desecProvider) minTTL(ctx context.Context, zone string) (int, error) {
	status, _, body, err := p.do(ctx, http.MethodGet, "/domains/"+dsDomain(zone)+"/", nil)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return 0, p.fail("could not read the domain", status, body)
	}
	var d struct {
		MinimumTTL int `json:"minimum_ttl"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return 0, fmt.Errorf("could not decode deSEC's answer: %w", err)
	}
	return d.MinimumTTL, nil
}

func (p *desecProvider) states(ctx context.Context, zone string) ([]rrsetState, error) {
	var out []rrsetState
	err := p.pages(ctx, "could not get records", "/domains/"+dsDomain(zone)+"/rrsets/", func(b []byte) error {
		var page []dsRRset
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		for _, s := range page {
			out = append(out, rrsetState{Name: gdName(s.Subname), Type: s.Type, TTL: s.TTL, Values: s.Records})
		}
		return nil
	})
	return out, err
}

func (p *desecProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	sets, err := p.states(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []libdns.Record
	for _, s := range sets {
		for _, v := range s.Values {
			out = append(out, fromPresentation(zone, s, v))
		}
	}
	return out, nil
}

// dsTTL brings a TTL into the domain's range; without one, deSEC's usual
// 3600 is used.
func dsTTL(ttl, min int) int {
	if ttl <= 0 {
		ttl = desecDefaultTTL
	}
	if ttl < min {
		ttl = min
	}
	if ttl > desecMaxTTL {
		ttl = desecMaxTTL
	}
	return ttl
}

// apply writes every change in one bulk request, which deSEC applies
// entirely or not at all.
func (p *desecProvider) apply(ctx context.Context, zone string, changes []rrsetChange) error {
	if len(changes) == 0 {
		return nil
	}
	min, err := p.minTTL(ctx, zone)
	if err != nil {
		return err
	}
	body := make([]dsRRset, len(changes))
	for i, c := range changes {
		sub := strings.ToLower(c.Name)
		if sub == "@" {
			sub = ""
		}
		body[i] = dsRRset{Subname: sub, Type: c.Type, TTL: dsTTL(c.TTL, min), Records: c.Values}
		if body[i].Records == nil {
			body[i].Records = []string{}
		}
	}
	status, _, out, err := p.do(ctx, http.MethodPut, "/domains/"+dsDomain(zone)+"/rrsets/", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return p.fail("could not write records", status, out)
	}
	return nil
}

// AppendRecords adds the values to their sets, keeping the ones already
// there. A TTL given in the input becomes the TTL of the whole set, as deSEC
// has one TTL per set.
func (p *desecProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	have, err := p.states(ctx, zone)
	if err != nil {
		return nil, err
	}
	changes, done, err := planAppend(zone, have, recs)
	if err != nil {
		return nil, err
	}
	if err := p.apply(ctx, zone, changes); err != nil {
		return nil, err
	}
	return done, nil
}

// SetRecords makes the given records the only members of their sets.
func (p *desecProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	changes, done, err := planSet(recs)
	if err != nil {
		return nil, err
	}
	if err := p.apply(ctx, zone, changes); err != nil {
		return nil, err
	}
	return done, nil
}

// DeleteRecords removes the values that match by name and, when the input
// states them, by type, value and TTL. Other values of a set stay.
func (p *desecProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	have, err := p.states(ctx, zone)
	if err != nil {
		return nil, err
	}
	changes, deleted := planDelete(zone, have, recs)
	if err := p.apply(ctx, zone, changes); err != nil {
		return nil, err
	}
	return deleted, nil
}
