package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// powerDNSProvider talks to the HTTP API of a PowerDNS Authoritative server
// (4.x and 5.x) itself. The libdns powerdns package (v0.1.4) is built on a
// pre-release libdns API (v1.0.0-beta.1) and a third-party client, and writes
// record sets one request at a time. Verified against PowerDNS 4.9.17 and
// 5.0.7 in Docker (2026-09-25):
//
//   - the key is sent as X-API-Key; a wrong one gets 401, an unknown zone or
//     server id 404, an invalid change 422 with a message;
//   - PowerDNS stores record sets: one PATCH of the zone carries several
//     REPLACE or DELETE changes and is applied entirely or not at all;
//   - names must be fully qualified; values are in presentation format, TXT
//     quoted (an unquoted TXT is refused), targets must end in a dot;
//   - every record set needs a TTL; any TTL is accepted;
//   - a REPLACE keeps the set's comments but drops records not listed, so
//     disabled records (read but not served) are sent again unchanged;
//   - a TXT string over 255 bytes is stored as given and split when served;
//   - every value is one string, SRV "0 0 443 target." included, so the
//     zero-value bug of issue #19 cannot occur;
//   - the SOA serial goes up on each change when the zone's SOA-EDIT-API is
//     set, as it is for zones created through the API.
type powerDNSProvider struct {
	APIURL, APIKey, ServerID string
	client                   *http.Client
}

const powerDNSDefaultTTL = 3600

// pdRRset is a record set as the PowerDNS API represents it.
type pdRRset struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	TTL        int        `json:"ttl,omitempty"`
	ChangeType string     `json:"changetype,omitempty"`
	Records    []pdRecord `json:"records"`
}

type pdRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// pdBaseURL turns the URL the administrator gave (with or without /api/v1)
// into the server's API root.
func pdBaseURL(apiURL, serverID string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("the API URL must start with http:// or https:// and name the server")
	}
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(p, "/api/v1")
	p = strings.TrimSuffix(p, "/api")
	if serverID == "" {
		serverID = "localhost"
	}
	return u.Scheme + "://" + u.Host + p + "/api/v1/servers/" + url.PathEscape(serverID), nil
}

func (p *powerDNSProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	base, err := pdBaseURL(p.APIURL, p.ServerID)
	if err != nil {
		return 0, nil, &contract.Error{Code: contract.CodeInvalidRequest, Message: err.Error()}
	}
	var rd io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-API-Key", p.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := p.client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		// The error names the URL, which holds no secret.
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return resp.StatusCode, out, err
}

// fail turns an error answer into a structured error where the status says
// what happened. PowerDNS's messages never contain the key.
func (p *powerDNSProvider) fail(what string, status int, body []byte) error {
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
	case http.StatusUnauthorized:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "PowerDNS rejected the API key"}
	case http.StatusForbidden:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "PowerDNS refused the request (" + msg + "); check the key and the server's webserver-allow-from"}
	case http.StatusNotFound:
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "PowerDNS has no such zone on server " + p.serverID() + " (" + msg + ")"}
	}
	return fmt.Errorf("%s: PowerDNS answered %d: %s", what, status, msg)
}

func (p *powerDNSProvider) serverID() string {
	if p.ServerID == "" {
		return "localhost"
	}
	return p.ServerID
}

// pdZone is the zone's canonical name, which is also its id in the API.
func pdZone(zone string) string { return strings.ToLower(strings.TrimSuffix(zone, ".")) + "." }

// ListZones lists the zones this server can change: native and primary ones,
// not secondaries or catalog zones.
func (p *powerDNSProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	status, body, err := p.do(ctx, http.MethodGet, "/zones", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, p.fail("could not list zones", status, body)
	}
	var zs []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &zs); err != nil {
		return nil, fmt.Errorf("could not decode PowerDNS's answer: %w", err)
	}
	var out []libdns.Zone
	for _, z := range zs {
		switch strings.ToLower(z.Kind) {
		case "native", "master", "primary":
			out = append(out, libdns.Zone{Name: z.Name})
		}
	}
	return out, nil
}

// pdState is a zone as read: its sets with enabled values (for the planning
// helpers), and the disabled records of each set, to be kept on writes.
type pdState struct {
	sets     []rrsetState
	disabled map[rrsetKey][]pdRecord
}

func (p *powerDNSProvider) read(ctx context.Context, zone string) (pdState, error) {
	st := pdState{disabled: map[rrsetKey][]pdRecord{}}
	status, body, err := p.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(pdZone(zone))+"?rrsets=true", nil)
	if err != nil {
		return st, err
	}
	if status != http.StatusOK {
		return st, p.fail("could not get records", status, body)
	}
	var z struct {
		RRsets []pdRRset `json:"rrsets"`
	}
	if err := json.Unmarshal(body, &z); err != nil {
		return st, fmt.Errorf("could not decode PowerDNS's answer: %w", err)
	}
	for _, s := range z.RRsets {
		name := libdns.RelativeName(s.Name, pdZone(zone))
		k := keyOf(s.Type, name)
		var values []string
		for _, r := range s.Records {
			if r.Disabled {
				st.disabled[k] = append(st.disabled[k], r)
			} else {
				values = append(values, r.Content)
			}
		}
		if len(values) > 0 {
			st.sets = append(st.sets, rrsetState{Name: name, Type: s.Type, TTL: s.TTL, Values: values})
		}
	}
	return st, nil
}

func (p *powerDNSProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	st, err := p.read(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []libdns.Record
	for _, s := range st.sets {
		for _, v := range s.Values {
			out = append(out, fromPresentation(zone, s, v))
		}
	}
	return out, nil
}

// apply writes every change in one PATCH, which PowerDNS applies entirely or
// not at all. A set's disabled records are kept.
func (p *powerDNSProvider) apply(ctx context.Context, zone string, st pdState, changes []rrsetChange) error {
	if len(changes) == 0 {
		return nil
	}
	ttls := map[rrsetKey]int{}
	for _, s := range st.sets {
		ttls[keyOf(s.Type, s.Name)] = s.TTL
	}
	sets := make([]pdRRset, len(changes))
	for i, c := range changes {
		k := keyOf(c.Type, c.Name)
		name := strings.ToLower(libdns.AbsoluteName(gdName(c.Name), pdZone(zone)))
		recs := []pdRecord{}
		for _, v := range c.Values {
			recs = append(recs, pdRecord{Content: v})
		}
		recs = append(recs, st.disabled[k]...)
		if len(recs) == 0 {
			sets[i] = pdRRset{Name: name, Type: c.Type, ChangeType: "DELETE", Records: []pdRecord{}}
			continue
		}
		ttl := c.TTL
		if ttl <= 0 {
			ttl = ttls[k]
		}
		if ttl <= 0 {
			ttl = powerDNSDefaultTTL
		}
		sets[i] = pdRRset{Name: name, Type: c.Type, TTL: ttl, ChangeType: "REPLACE", Records: recs}
	}
	status, body, err := p.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(pdZone(zone)), map[string]any{"rrsets": sets})
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return p.fail("could not write records", status, body)
	}
	return nil
}

// AppendRecords adds the values to their sets, keeping the ones already
// there. A TTL given in the input becomes the TTL of the whole set, as
// PowerDNS has one TTL per set.
func (p *powerDNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	st, err := p.read(ctx, zone)
	if err != nil {
		return nil, err
	}
	changes, done, err := planAppend(zone, st.sets, recs)
	if err != nil {
		return nil, err
	}
	if err := p.apply(ctx, zone, st, changes); err != nil {
		return nil, err
	}
	return done, nil
}

// SetRecords makes the given records the only members of their sets.
func (p *powerDNSProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	changes, done, err := planSet(recs)
	if err != nil {
		return nil, err
	}
	st, err := p.read(ctx, zone)
	if err != nil {
		return nil, err
	}
	if err := p.apply(ctx, zone, st, changes); err != nil {
		return nil, err
	}
	return done, nil
}

// DeleteRecords removes the values that match by name and, when the input
// states them, by type, value and TTL. Other values of a set stay.
func (p *powerDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	st, err := p.read(ctx, zone)
	if err != nil {
		return nil, err
	}
	changes, deleted := planDelete(zone, st.sets, recs)
	if err := p.apply(ctx, zone, st, changes); err != nil {
		return nil, err
	}
	return deleted, nil
}
