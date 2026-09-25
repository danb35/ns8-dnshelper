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

func (s gnRRset) state() rrsetState {
	return rrsetState{Name: s.Name, Type: s.Type, TTL: s.TTL, Values: s.Values}
}

func (g *gandiProvider) states(ctx context.Context, zone string) ([]rrsetState, error) {
	sets, err := g.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]rrsetState, len(sets))
	for i, s := range sets {
		out[i] = s.state()
	}
	return out, nil
}

func (g *gandiProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	sets, err := g.states(ctx, zone)
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

// gnTTL brings a TTL into Gandi's range; 0 stays 0 and lets Gandi choose.
func gnTTL(ttl int) int {
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

// put replaces a set with its new values, or removes it when there are none.
// Gandi has no call that writes several sets at once.
func (g *gandiProvider) put(ctx context.Context, zone string, c rrsetChange) error {
	path := "/domains/" + gnDomain(zone) + "/records/" + url.PathEscape(gdName(c.Name)) + "/" + url.PathEscape(c.Type)
	if len(c.Values) == 0 {
		status, body, err := g.do(ctx, http.MethodDelete, path, nil)
		if err != nil {
			return err
		}
		if status != http.StatusNoContent && status != http.StatusOK && status != http.StatusNotFound {
			return g.fail("could not delete "+c.Type+" records", status, body)
		}
		return nil
	}
	status, body, err := g.do(ctx, http.MethodPut, path, gnRRset{TTL: gnTTL(c.TTL), Values: c.Values})
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return g.fail("could not write "+c.Type+" records", status, body)
	}
	return nil
}

func (g *gandiProvider) apply(ctx context.Context, zone string, changes []rrsetChange) error {
	for _, c := range changes {
		if err := g.put(ctx, zone, c); err != nil {
			return err
		}
	}
	return nil
}

// AppendRecords adds the values to their sets, keeping the ones already
// there. A TTL given in the input becomes the TTL of the whole set, as Gandi
// has one TTL per set.
func (g *gandiProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	have, err := g.states(ctx, zone)
	if err != nil {
		return nil, err
	}
	changes, done, err := planAppend(zone, have, recs)
	if err != nil {
		return nil, err
	}
	if err := g.apply(ctx, zone, changes); err != nil {
		return nil, err
	}
	return done, nil
}

// SetRecords makes the given records the only members of their sets.
func (g *gandiProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	changes, done, err := planSet(recs)
	if err != nil {
		return nil, err
	}
	if err := g.apply(ctx, zone, changes); err != nil {
		return nil, err
	}
	return done, nil
}

// DeleteRecords removes the values that match by name and, when the input
// states them, by type, value and TTL. Other values of a set stay.
func (g *gandiProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	have, err := g.states(ctx, zone)
	if err != nil {
		return nil, err
	}
	changes, deleted := planDelete(zone, have, recs)
	if err := g.apply(ctx, zone, changes); err != nil {
		return nil, err
	}
	return deleted, nil
}
