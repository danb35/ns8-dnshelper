package registry

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// ovhProvider talks to the OVHcloud API (/1.0/domain/zone) itself. The libdns
// ovh package (v1.1.0) only knows the older application key, application
// secret and consumer key login, not the OAuth2 service accounts OVHcloud now
// recommends. Both are accepted here. Verified against the API (2026-09-28,
// with a service account):
//
//   - a service account (client ID "EU.xxxx" and secret) gets a bearer token
//     from the region's OAuth2 token endpoint (client credentials, scope
//     "all"); what it may do is set by an IAM policy. A request outside the
//     policy gets 403 "User not granted for this request";
//   - an application key is signed per request: "$1$" + SHA-1 of
//     secret+consumer+METHOD+URL+body+timestamp, with the timestamp taken
//     from the API's /auth/time (not tested live);
//   - records have numeric IDs; the list only gives IDs (filterable by
//     fieldType and subDomain, case-insensitively), so each record is read
//     on its own; names are relative ("" is the apex), stored in lower case;
//   - a record's value is one "target" string in zone-file form: "10 mx.
//     example.net." for MX, "0 0 443 target." for SRV (so a zero priority
//     or weight cannot be dropped, issue #19). A target without the final
//     dot is stored as sent and read as relative to the zone;
//   - a TXT target sent as plain text is quoted and escaped by OVH; one sent
//     already quoted is stored as sent, \" and \\ included, but \DDD is
//     stored as a literal backslash, so non-ASCII letters are sent as they
//     are. Long values are split into 255-byte strings;
//   - SPF, DKIM and DMARC are extra types of OVH's web interface, served as
//     TXT; they are read as TXT here;
//   - the TTL is at most 86400 and at least 60 (OVH raises shorter ones);
//     0 means the zone's default;
//   - changes are only published when the zone is refreshed, which is done
//     after every change.
type ovhProvider struct {
	Endpoint                       string // ovh-eu, ovh-ca or ovh-us
	ClientID, ClientSecret         string
	AppKey, AppSecret, ConsumerKey string
	baseURL, tokenURL              string // overridden in tests
	client                         *http.Client
	mu                             sync.Mutex
	token                          string
	timeDelta                      *time.Duration
	now                            func() time.Time // overridden in tests
}

type ovhRegion struct{ api, token string }

var ovhRegions = map[string]ovhRegion{
	"ovh-eu": {"https://eu.api.ovh.com/1.0", "https://www.ovh.com/auth/oauth2/token"},
	"ovh-ca": {"https://ca.api.ovh.com/1.0", "https://ca.ovh.com/auth/oauth2/token"},
	"ovh-us": {"https://api.us.ovhcloud.com/1.0", "https://us.ovhcloud.com/auth/oauth2/token"},
}

const ovhMinTTL = 60

// ovhVerify checks the endpoint and that exactly one kind of login is given.
func ovhVerify(c map[string]string) string {
	if _, ok := ovhRegions[c["endpoint"]]; !ok {
		return "endpoint must be ovh-eu, ovh-ca or ovh-us"
	}
	oauth := c["client_id"] != "" || c["client_secret"] != ""
	app := c["application_key"] != "" || c["application_secret"] != "" || c["consumer_key"] != ""
	switch {
	case oauth && app:
		return "give either client_id and client_secret or application_key, application_secret and consumer_key, not both"
	case oauth && (c["client_id"] == "" || c["client_secret"] == ""):
		return "missing credential fields: client_id and client_secret are both needed"
	case app && (c["application_key"] == "" || c["application_secret"] == "" || c["consumer_key"] == ""):
		return "missing credential fields: application_key, application_secret and consumer_key are all needed"
	case !oauth && !app:
		return "missing credential fields: client_id and client_secret (or application_key, application_secret and consumer_key)"
	}
	return ""
}

// ovhRecord is a record as the OVH API represents it.
type ovhRecord struct {
	ID        int64  `json:"id,omitempty"`
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl,omitempty"`
}

func (p *ovhProvider) urls() (api, token string) {
	r := ovhRegions[p.Endpoint]
	if r.api == "" {
		r = ovhRegions["ovh-eu"]
	}
	api, token = r.api, r.token
	if p.baseURL != "" {
		api = p.baseURL
	}
	if p.tokenURL != "" {
		token = p.tokenURL
	}
	return api, token
}

func (p *ovhProvider) httpClient() *http.Client {
	if p.client == nil {
		p.client = &http.Client{Timeout: 30 * time.Second}
	}
	return p.client
}

// bearer gets (once per run) an OAuth2 access token for the service account.
func (p *ovhProvider) bearer(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" {
		return p.token, nil
	}
	_, tokenURL := p.urls()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"all"}, "client_id": {p.ClientID}, "client_secret": {p.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &tok)
	if resp.StatusCode == http.StatusOK && tok.AccessToken != "" {
		p.token = tok.AccessToken
		return p.token, nil
	}
	msg := tok.Error
	if tok.Description != "" {
		msg += ": " + tok.Description
	}
	if msg == "" {
		msg = "HTTP " + strconv.Itoa(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", &contract.Error{Code: contract.CodeAuthFailed, Message: "OVHcloud refused the service account (" + scrub(msg, p.ClientSecret) + "); check the client ID, the secret and the endpoint"}
	}
	return "", fmt.Errorf("could not get an OVHcloud access token: %s", scrub(msg, p.ClientSecret))
}

func scrub(s, secret string) string {
	if secret != "" {
		s = strings.ReplaceAll(s, secret, "***")
	}
	return s
}

// serverTime returns OVH's clock, for signing: the API refuses a timestamp
// too far from its own.
func (p *ovhProvider) serverTime(ctx context.Context) (time.Time, error) {
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	p.mu.Lock()
	d := p.timeDelta
	p.mu.Unlock()
	if d != nil {
		return now().Add(-*d), nil
	}
	api, _ := p.urls()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"/auth/time", nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	secs, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if resp.StatusCode != http.StatusOK || err != nil {
		return time.Time{}, fmt.Errorf("could not read OVHcloud's time (HTTP %d)", resp.StatusCode)
	}
	delta := now().Sub(time.Unix(secs, 0))
	p.mu.Lock()
	p.timeDelta = &delta
	p.mu.Unlock()
	return now().Add(-delta), nil
}

// ovhSignature is the application-key signature of one request.
func ovhSignature(appSecret, consumerKey, method, target string, body []byte, ts int64) string {
	return fmt.Sprintf("$1$%x", sha1.Sum([]byte(fmt.Sprintf("%s+%s+%s+%s+%s+%d", appSecret, consumerKey, method, target, body, ts))))
}

// do sends one request. A 429 is retried a few times.
func (p *ovhProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	api, _ := p.urls()
	target := api + path
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json;charset=utf-8")
		}
		if p.AppKey != "" {
			now, err := p.serverTime(ctx)
			if err != nil {
				return 0, nil, err
			}
			ts := now.Unix()
			req.Header.Set("X-Ovh-Application", p.AppKey)
			req.Header.Set("X-Ovh-Consumer", p.ConsumerKey)
			req.Header.Set("X-Ovh-Timestamp", strconv.FormatInt(ts, 10))
			req.Header.Set("X-Ovh-Signature", ovhSignature(p.AppSecret, p.ConsumerKey, method, target, payload, ts))
		} else {
			tok, err := p.bearer(ctx)
			if err != nil {
				return 0, nil, err
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := p.httpClient().Do(req)
		if err != nil {
			return 0, nil, err
		}
		out, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests || attempt >= 4 || err != nil {
			return resp.StatusCode, out, err
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// fail turns an error answer ({"class": ..., "message": ...}) into a
// structured error. The answer never contains the credentials.
func (p *ovhProvider) fail(what string, status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	var e struct {
		Class   string `json:"class"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		msg = e.Message
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	switch status {
	case http.StatusUnauthorized:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "OVHcloud refused the credentials (" + msg + ")"}
	case http.StatusForbidden:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "OVHcloud refused the request (" + msg + "); check that the service account's IAM policy (or the consumer key's access rules) covers this zone"}
	case http.StatusNotFound:
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "OVHcloud has no such zone for these credentials (" + msg + ")"}
	}
	return fmt.Errorf("%s: OVHcloud answered %d: %s", what, status, msg)
}

func ovhZone(zone string) string { return strings.ToLower(strings.TrimSuffix(zone, ".")) }

func (p *ovhProvider) zonePath(zone string) string {
	return "/domain/zone/" + url.PathEscape(ovhZone(zone))
}

func (p *ovhProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	status, body, err := p.do(ctx, http.MethodGet, "/domain/zone", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, p.fail("could not list zones", status, body)
	}
	var names []string
	if err := json.Unmarshal(body, &names); err != nil {
		return nil, fmt.Errorf("could not decode OVHcloud's answer: %w", err)
	}
	out := make([]libdns.Zone, len(names))
	for i, n := range names {
		out[i] = libdns.Zone{Name: ovhZone(n) + "."}
	}
	return out, nil
}

// list reads the zone's records, or only those named sub (relative, "" for
// the apex) when byName is set. The API lists IDs only, so the records are
// then read a few at a time.
func (p *ovhProvider) list(ctx context.Context, zone string, byName bool, sub string) ([]ovhRecord, error) {
	path := p.zonePath(zone) + "/record"
	if byName {
		path += "?subDomain=" + url.QueryEscape(sub)
	}
	status, body, err := p.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, p.fail("could not list records", status, body)
	}
	var ids []int64
	if err := json.Unmarshal(body, &ids); err != nil {
		return nil, fmt.Errorf("could not decode OVHcloud's answer: %w", err)
	}
	out := make([]ovhRecord, len(ids))
	errs := make([]error, len(ids))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, id int64) {
			defer func() { <-sem; wg.Done() }()
			status, body, err := p.do(ctx, http.MethodGet, p.zonePath(zone)+"/record/"+strconv.FormatInt(id, 10), nil)
			switch {
			case err != nil:
				errs[i] = err
			case status != http.StatusOK:
				errs[i] = p.fail("could not read a record", status, body)
			default:
				errs[i] = json.Unmarshal(body, &out[i])
			}
		}(i, id)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	// A record named with a subdomain filter must match it exactly; the
	// filter is not documented as exact.
	if byName {
		kept := out[:0]
		for _, r := range out {
			if strings.EqualFold(r.SubDomain, sub) {
				kept = append(kept, r)
			}
		}
		out = kept
	}
	return out, nil
}

func (p *ovhProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := p.list(ctx, zone, false, "")
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		out[i] = r.toLibdns(zone)
	}
	return out, nil
}

// ovhTXTTypes are OVH's own record types that are served as TXT.
var ovhTXTTypes = map[string]bool{"TXT": true, "SPF": true, "DKIM": true, "DMARC": true}

// toLibdns renders the record in libdns' text form: TXT unquoted, targets
// with a final dot.
func (r ovhRecord) toLibdns(zone string) libdns.RR {
	typ := strings.ToUpper(r.FieldType)
	data := r.Target
	switch {
	case ovhTXTTypes[typ]:
		typ, data = "TXT", txtUnquote(data)
	case typ == "A" || typ == "AAAA":
		if a, err := netip.ParseAddr(data); err == nil {
			data = a.String()
		}
	case hasTarget[typ]:
		if f := strings.Fields(data); len(f) > 0 {
			f[len(f)-1] = qualifyTarget(f[len(f)-1], ovhZone(zone))
			data = strings.Join(f, " ")
		}
	}
	name := r.SubDomain
	if name == "" {
		name = "@"
	}
	return libdns.RR{Name: strings.ToLower(name), Type: typ, TTL: time.Duration(r.TTL) * time.Second, Data: data}
}

// ovhFromLibdns converts a record to the API form.
func ovhFromLibdns(zone string, rec libdns.Record) (ovhRecord, error) {
	rr := rec.RR()
	sub := strings.ToLower(libdns.RelativeName(libdns.AbsoluteName(gdName(rr.Name), ovhZone(zone)+"."), ovhZone(zone)+"."))
	if sub == "@" {
		sub = ""
	}
	out := ovhRecord{FieldType: strings.ToUpper(rr.Type), SubDomain: sub, Target: rr.Data, TTL: int(rr.TTL / time.Second)}
	if out.TTL > 0 && out.TTL < ovhMinTTL {
		out.TTL = ovhMinTTL
	}
	f := strings.Fields(rr.Data)
	switch out.FieldType {
	case "TXT", "SPF":
		out.FieldType, out.Target = "TXT", txtQuote(rr.Data)
	case "MX":
		if len(f) != 2 {
			return out, fmt.Errorf("MX data must be \"priority target\"")
		}
		if _, err := gdInt(f[0]); err != nil {
			return out, err
		}
	case "SRV":
		if len(f) != 4 {
			return out, fmt.Errorf("SRV data must be \"priority weight port target\"")
		}
		for _, n := range f[:3] {
			if _, err := gdInt(n); err != nil {
				return out, err
			}
		}
	}
	if hasTarget[out.FieldType] && len(f) > 0 {
		f[len(f)-1] = pbFQDN(f[len(f)-1])
		out.Target = strings.Join(f, " ")
	}
	return out, nil
}

func (p *ovhProvider) create(ctx context.Context, zone string, r ovhRecord) (ovhRecord, error) {
	status, body, err := p.do(ctx, http.MethodPost, p.zonePath(zone)+"/record", r)
	if err != nil {
		return r, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return r, p.fail("could not create a "+r.FieldType+" record", status, body)
	}
	var made ovhRecord
	if err := json.Unmarshal(body, &made); err != nil {
		return r, fmt.Errorf("could not decode OVHcloud's answer: %w", err)
	}
	return made, nil
}

func (p *ovhProvider) remove(ctx context.Context, zone string, id int64) error {
	status, body, err := p.do(ctx, http.MethodDelete, p.zonePath(zone)+"/record/"+strconv.FormatInt(id, 10), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return p.fail("could not delete a record", status, body)
	}
	return nil
}

// refresh publishes the zone's changes to OVH's name servers.
func (p *ovhProvider) refresh(ctx context.Context, zone string) error {
	status, body, err := p.do(ctx, http.MethodPost, p.zonePath(zone)+"/refresh", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return p.fail("the records were changed but the zone could not be refreshed", status, body)
	}
	return nil
}

// byName reads the records at each name the input mentions.
func (p *ovhProvider) byName(ctx context.Context, zone string, recs []libdns.Record) ([]ovhRecord, error) {
	seen := map[string]bool{}
	var out []ovhRecord
	for _, r := range recs {
		w, err := ovhFromLibdns(zone, libdns.RR{Name: r.RR().Name})
		if err != nil {
			return nil, err
		}
		if seen[w.SubDomain] {
			continue
		}
		seen[w.SubDomain] = true
		got, err := p.list(ctx, zone, true, w.SubDomain)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// AppendRecords creates the records, then refreshes the zone.
func (p *ovhProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in := make([]ovhRecord, len(recs))
	for i, r := range recs {
		var err error
		if in[i], err = ovhFromLibdns(zone, r); err != nil {
			return nil, err
		}
	}
	var out []libdns.Record
	for _, r := range in {
		made, err := p.create(ctx, zone, r)
		if err != nil {
			if len(out) > 0 {
				_ = p.refresh(ctx, zone)
			}
			return out, err
		}
		out = append(out, made.toLibdns(zone))
	}
	if len(out) > 0 {
		if err := p.refresh(ctx, zone); err != nil {
			return out, err
		}
	}
	return out, nil
}

// DeleteRecords removes the records that match by name and, when the input
// states them, by type, value and TTL, then refreshes the zone.
func (p *ovhProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	existing, err := p.byName(ctx, zone, recs)
	if err != nil {
		return nil, err
	}
	var deleted []libdns.Record
	for _, e := range existing {
		have := e.toLibdns(zone)
		for _, w := range recs {
			if vuSame(have, w.RR()) {
				if err := p.remove(ctx, zone, e.ID); err != nil {
					if len(deleted) > 0 {
						_ = p.refresh(ctx, zone)
					}
					return deleted, err
				}
				deleted = append(deleted, have)
				break
			}
		}
	}
	if len(deleted) > 0 {
		if err := p.refresh(ctx, zone); err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// SetRecords makes the given records the only members of their sets: members
// with another value are deleted, missing ones created, equal ones left alone.
// The zone is refreshed once at the end.
func (p *ovhProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	in := make([]ovhRecord, len(recs))
	for i, r := range recs {
		var err error
		if in[i], err = ovhFromLibdns(zone, r); err != nil {
			return nil, err
		}
	}
	existing, err := p.byName(ctx, zone, recs)
	if err != nil {
		return nil, err
	}
	changed := false
	finish := func(err error) error {
		if changed {
			if rerr := p.refresh(ctx, zone); err == nil {
				err = rerr
			}
		}
		return err
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
			if err := p.remove(ctx, zone, e.ID); err != nil {
				return nil, finish(err)
			}
			changed = true
		}
	}
	for i, r := range in {
		if kept[i] {
			continue
		}
		if _, err := p.create(ctx, zone, r); err != nil {
			return nil, finish(err)
		}
		changed = true
	}
	return recs, finish(nil)
}
