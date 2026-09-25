package registry

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// googleDNSProvider talks to the Google Cloud DNS API (v1) itself. The libdns
// googleclouddns package (v1.2.0) reads the service account key from a file
// path (the key would have to be written to disk), falls back to whatever
// Google credentials the machine has when none is given, and pulls in Google's
// whole API client. Verified against the API (2026-09-25):
//
//   - a service account key (the JSON file) signs a JWT that is exchanged for
//     an access token at the key's token_uri; a key Google does not accept
//     gets "invalid_grant";
//   - Cloud DNS stores record sets; a change lists the sets to delete (exactly
//     as they are) and the sets to add, and is applied entirely or not at all;
//   - names are fully qualified; values are in presentation format, TXT
//     quoted; every set needs a TTL;
//   - every value is one string, SRV "0 0 443 target." included, so the
//     zero-value bug of issue #19 cannot occur;
//   - a zone is found by its DNS name among the project's public managed zones.
type googleDNSProvider struct {
	KeyJSON, Project string
	baseURL          string // overridden in tests
	client           *http.Client
	token            string
	tokenExpiry      time.Time
	zones            map[string]string // dnsName -> managed zone name
}

const (
	googleDNSBase       = "https://dns.googleapis.com/dns/v1"
	googleDNSScope      = "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
	googleDNSDefaultTTL = 300
)

// gcpKey is the part of a service account key file that is used.
type gcpKey struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

// parseGCPKey reads a service account key file. Its errors never contain the
// key.
func parseGCPKey(s string) (gcpKey, *rsa.PrivateKey, error) {
	var k gcpKey
	if err := json.Unmarshal([]byte(s), &k); err != nil {
		return k, nil, fmt.Errorf("the service account key is not a JSON key file")
	}
	if k.Type != "service_account" || k.ClientEmail == "" || k.PrivateKey == "" {
		return k, nil, fmt.Errorf("the service account key must be the JSON file of a service account (type service_account)")
	}
	if k.TokenURI == "" {
		k.TokenURI = "https://oauth2.googleapis.com/token"
	}
	if u, err := url.Parse(k.TokenURI); err != nil || u.Scheme != "https" {
		return k, nil, fmt.Errorf("the service account key's token_uri must be an https URL")
	}
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return k, nil, fmt.Errorf("the service account key's private_key is not a PEM key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return k, nil, fmt.Errorf("the service account key's private_key cannot be read")
		}
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return k, nil, fmt.Errorf("the service account key's private_key is not an RSA key")
	}
	return k, rsaKey, nil
}

func (p *googleDNSProvider) httpClient() *http.Client {
	if p.client == nil {
		p.client = &http.Client{Timeout: 30 * time.Second}
	}
	return p.client
}

func (p *googleDNSProvider) project() (string, error) {
	if p.Project != "" {
		return p.Project, nil
	}
	k, _, err := parseGCPKey(p.KeyJSON)
	if err != nil {
		return "", &contract.Error{Code: contract.CodeInvalidRequest, Message: err.Error()}
	}
	return k.ProjectID, nil
}

// accessToken signs a JWT with the service account key and exchanges it for
// an access token, kept for the rest of the run.
func (p *googleDNSProvider) accessToken(ctx context.Context) (string, error) {
	if p.token != "" && time.Now().Before(p.tokenExpiry) {
		return p.token, nil
	}
	k, key, err := parseGCPKey(p.KeyJSON)
	if err != nil {
		return "", &contract.Error{Code: contract.CodeInvalidRequest, Message: err.Error()}
	}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	now := time.Now()
	head := map[string]string{"alg": "RS256", "typ": "JWT"}
	if k.PrivateKeyID != "" {
		head["kid"] = k.PrivateKeyID
	}
	unsigned := enc(head) + "." + enc(map[string]any{
		"iss": k.ClientEmail, "scope": googleDNSScope, "aud": k.TokenURI,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("could not sign the token request")
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion": {unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &t)
	if resp.StatusCode != http.StatusOK || t.AccessToken == "" {
		msg := strings.TrimSpace(t.Error + ": " + t.Description)
		if t.Error == "" {
			msg = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return "", &contract.Error{Code: contract.CodeAuthFailed, Message: "Google did not accept the service account key (" + msg + ")"}
	}
	p.token = t.AccessToken
	p.tokenExpiry = now.Add(time.Duration(t.ExpiresIn)*time.Second - time.Minute)
	return p.token, nil
}

func (p *googleDNSProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	token, err := p.accessToken(ctx)
	if err != nil {
		return 0, nil, err
	}
	project, err := p.project()
	if err != nil {
		return 0, nil, err
	}
	var payload []byte
	if body != nil {
		if payload, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	base := p.baseURL
	if base == "" {
		base = googleDNSBase
	}
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+"/projects/"+url.PathEscape(project)+path, rd)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := p.httpClient().Do(req)
		if err != nil {
			return 0, nil, err
		}
		out, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests && attempt < 4 && err == nil {
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		return resp.StatusCode, out, err
	}
}

// fail turns an error answer into a structured error. Google's messages
// never contain the key or the token.
func (p *googleDNSProvider) fail(what string, status int, body []byte) error {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		msg = e.Error.Message
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	switch status {
	case http.StatusUnauthorized:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "Google refused the service account (" + msg + ")"}
	case http.StatusForbidden:
		return &contract.Error{Code: contract.CodeAuthFailed, Message: "the service account may not do this in the project (" + msg + "); give it the DNS Administrator role and check that the Cloud DNS API is enabled"}
	case http.StatusNotFound:
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "Google Cloud DNS has no such project or zone (" + msg + ")"}
	case http.StatusConflict, http.StatusPreconditionFailed:
		return fmt.Errorf("%s: the records changed at Google meanwhile, try again (%s)", what, msg)
	}
	return fmt.Errorf("%s: Google Cloud DNS answered %d: %s", what, status, msg)
}

// listZones reads the project's public managed zones: DNS name -> zone name.
func (p *googleDNSProvider) listZones(ctx context.Context) (map[string]string, error) {
	if p.zones != nil {
		return p.zones, nil
	}
	zones := map[string]string{}
	token := ""
	for {
		path := "/managedZones?maxResults=500"
		if token != "" {
			path += "&pageToken=" + url.QueryEscape(token)
		}
		status, body, err := p.do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, p.fail("could not list zones", status, body)
		}
		var res struct {
			ManagedZones []struct {
				Name       string `json:"name"`
				DNSName    string `json:"dnsName"`
				Visibility string `json:"visibility"`
			} `json:"managedZones"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return nil, fmt.Errorf("could not decode Google's answer: %w", err)
		}
		for _, z := range res.ManagedZones {
			if z.Visibility == "" || z.Visibility == "public" {
				zones[strings.ToLower(z.DNSName)] = z.Name
			}
		}
		if res.NextPageToken == "" {
			break
		}
		token = res.NextPageToken
	}
	p.zones = zones
	return zones, nil
}

func (p *googleDNSProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	zones, err := p.listZones(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Zone, 0, len(zones))
	for name := range zones {
		out = append(out, libdns.Zone{Name: name})
	}
	return out, nil
}

// managedZone finds the managed zone serving zone.
func (p *googleDNSProvider) managedZone(ctx context.Context, zone string) (string, error) {
	zones, err := p.listZones(ctx)
	if err != nil {
		return "", err
	}
	name, ok := zones[strings.ToLower(strings.TrimSuffix(zone, "."))+"."]
	if !ok {
		return "", &contract.Error{Code: contract.CodeZoneNotFound, Message: "the Google Cloud project has no public managed zone for " + strings.TrimSuffix(zone, ".")}
	}
	return name, nil
}

// gdnsRRset is a record set as the Cloud DNS API represents it.
type gdnsRRset struct {
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	TTL           int             `json:"ttl"`
	Rrdatas       []string        `json:"rrdatas,omitempty"`
	RoutingPolicy json.RawMessage `json:"routingPolicy,omitempty"`
}

// gdnsState is a zone as read: the managed zone, its sets for the planning
// helpers, and each set exactly as Google has it, which a change must name to
// delete it.
type gdnsState struct {
	managed string
	sets    []rrsetState
	raw     map[rrsetKey]gdnsRRset
}

func (p *googleDNSProvider) read(ctx context.Context, zone string) (gdnsState, error) {
	st := gdnsState{raw: map[rrsetKey]gdnsRRset{}}
	var err error
	if st.managed, err = p.managedZone(ctx, zone); err != nil {
		return st, err
	}
	token := ""
	for {
		path := "/managedZones/" + url.PathEscape(st.managed) + "/rrsets?maxResults=1000"
		if token != "" {
			path += "&pageToken=" + url.QueryEscape(token)
		}
		status, body, err := p.do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return st, err
		}
		if status != http.StatusOK {
			return st, p.fail("could not get records", status, body)
		}
		var res struct {
			Rrsets        []gdnsRRset `json:"rrsets"`
			NextPageToken string      `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return st, fmt.Errorf("could not decode Google's answer: %w", err)
		}
		for _, s := range res.Rrsets {
			name := libdns.RelativeName(s.Name, pdZone(zone))
			k := keyOf(s.Type, name)
			st.raw[k] = s
			if len(s.Rrdatas) > 0 {
				st.sets = append(st.sets, rrsetState{Name: name, Type: s.Type, TTL: s.TTL, Values: s.Rrdatas})
			}
		}
		if res.NextPageToken == "" {
			return st, nil
		}
		token = res.NextPageToken
	}
}

func (p *googleDNSProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
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

// apply sends every change as one Cloud DNS change: each touched set is
// deleted as it is and added back with its new values. Google applies a change
// entirely or not at all; apply waits until it is done.
func (p *googleDNSProvider) apply(ctx context.Context, zone string, st gdnsState, changes []rrsetChange) error {
	if len(changes) == 0 {
		return nil
	}
	var add, del []gdnsRRset
	for _, c := range changes {
		k := keyOf(c.Type, c.Name)
		old, exists := st.raw[k]
		if exists && len(old.RoutingPolicy) > 0 && string(old.RoutingPolicy) != "null" {
			return &contract.Error{Code: contract.CodeUnsupported, Message: "the " + c.Type + " records of " + gdName(c.Name) + " use a Cloud DNS routing policy, which dnshelper does not change"}
		}
		if exists {
			del = append(del, old)
		}
		if len(c.Values) == 0 {
			continue
		}
		ttl := c.TTL
		if ttl <= 0 {
			ttl = old.TTL
		}
		if ttl <= 0 {
			ttl = googleDNSDefaultTTL
		}
		values := c.Values
		if isTXT(c.Type) {
			values = make([]string, len(c.Values))
			for i, v := range c.Values {
				values[i] = escapeNonASCII(v)
			}
		}
		add = append(add, gdnsRRset{Name: strings.ToLower(libdns.AbsoluteName(gdName(c.Name), pdZone(zone))), Type: c.Type, TTL: ttl, Rrdatas: values})
	}
	body := map[string]any{}
	if len(add) > 0 {
		body["additions"] = add
	}
	if len(del) > 0 {
		body["deletions"] = del
	}
	path := "/managedZones/" + url.PathEscape(st.managed) + "/changes"
	status, out, err := p.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return p.fail("could not write records", status, out)
	}
	var ch struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(out, &ch); err != nil {
		return fmt.Errorf("could not decode Google's answer: %w", err)
	}
	for ch.Status == "pending" {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		status, out, err := p.do(ctx, http.MethodGet, path+"/"+url.PathEscape(ch.ID), nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return p.fail("could not follow the change", status, out)
		}
		if err := json.Unmarshal(out, &ch); err != nil {
			return fmt.Errorf("could not decode Google's answer: %w", err)
		}
	}
	return nil
}

// AppendRecords adds the values to their sets, keeping the ones already
// there. A TTL given in the input becomes the TTL of the whole set, as Cloud
// DNS has one TTL per set.
func (p *googleDNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
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
func (p *googleDNSProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
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
func (p *googleDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
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
