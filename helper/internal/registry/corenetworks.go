package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// coreNetworksProvider talks to the Core-Networks DNS API
// (https://beta.api.core-networks.de/doc/); libdns has no package for it. The API
// works differently from most DNS APIs, and the adapter is shaped by that:
//
//   - a bearer token is obtained by posting the API account's login and password,
//     and it expires, so it is fetched on first use and again when it runs out;
//   - changes to a zone are held in a database and reach the name servers only
//     when the zone is committed, so every change is followed by a commit;
//   - deleting posts a partial record and removes everything that matches it, and
//     a body without any field removes every record of the zone. The adapter
//     therefore only ever sends a delete for a concrete record it has just read
//     (name, type and data all set);
//   - there is no update or replace, so a set is a delete followed by adds;
//   - a TXT value is stored exactly as sent and read as zone-file text: plain text
//     (even a 600 character DKIM key) is served as one string, split at 255 bytes by
//     the service, but any value containing a quote or backslash is tokenized at
//     spaces and loses its backslashes, so those are sent as quoted, escaped
//     strings; values that were entered that way (an SPF record in quotes) are
//     decoded when read;
//   - a TTL below 60 seconds is refused, and none at all means 1800;
//   - a bad password answers 401 at login, a bad or expired token 403.
type coreNetworksProvider struct {
	Login, Password string
	baseURL         string // overridden in tests
	client          *http.Client
	cacheDir        string // where the session token is kept between runs; empty: nowhere

	mu      sync.Mutex // guards token and expires
	token   string
	expires time.Time
}

const (
	coreNetworksBase = "https://beta.api.core-networks.de"
	// the lowest TTL the service accepts (verified: 60 is, 59 and below are not)
	coreNetworksMinTTL = 60
)

// cnRecord is a record as the API represents it. The API documents ttl as a
// number but returns it as a string, so both are accepted.
type cnRecord struct {
	Name string          `json:"name"`
	TTL  json.RawMessage `json:"ttl,omitempty"`
	Type string          `json:"type"`
	Data string          `json:"data"`
}

func (r cnRecord) ttl() time.Duration {
	s := strings.Trim(string(r.TTL), `"`)
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

func (g *coreNetworksProvider) httpClient() *http.Client {
	if g.client != nil {
		return g.client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (g *coreNetworksProvider) base() string {
	if g.baseURL != "" {
		return g.baseURL
	}
	return coreNetworksBase
}

// tokenFile is where the session token for this account is kept. The name is a
// hash of everything the token depends on, so a changed password or another
// account never finds a token that is not theirs.
func (g *coreNetworksProvider) tokenFile() string {
	if g.cacheDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(g.Login + "\x00" + g.Password + "\x00" + g.base()))
	return filepath.Join(g.cacheDir, "corenetworks-"+hex.EncodeToString(sum[:12])+".json")
}

func (g *coreNetworksProvider) loadToken() {
	f := g.tokenFile()
	if f == "" {
		return
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return
	}
	var c struct {
		Token   string `json:"token"`
		Expires int64  `json:"expires"`
	}
	if json.Unmarshal(b, &c) != nil || c.Token == "" {
		return
	}
	g.token, g.expires = c.Token, time.Unix(c.Expires, 0)
}

// saveToken keeps the token for the next run, readable only by the current user.
// A failure to save is not an error: the next run logs in again.
func (g *coreNetworksProvider) saveToken() {
	f := g.tokenFile()
	if f == "" {
		return
	}
	if os.MkdirAll(g.cacheDir, 0o700) != nil {
		return
	}
	b, _ := json.Marshal(map[string]any{"token": g.token, "expires": g.expires.Unix()})
	tmp, err := os.CreateTemp(g.cacheDir, ".token-*") // created 0600
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr != nil || cerr != nil || os.Rename(tmp.Name(), f) != nil {
		os.Remove(tmp.Name())
	}
}

// forgetToken drops a token the service no longer accepts.
func (g *coreNetworksProvider) forgetToken() {
	g.mu.Lock()
	g.token = ""
	g.mu.Unlock()
	if f := g.tokenFile(); f != "" {
		os.Remove(f)
	}
}

// authorize returns a valid token: the one in memory or kept from an earlier run,
// or a new one. Logins are rate limited (a few in a short time are answered with
// 429), and a token lasts an hour, so a token is reused wherever it is kept.
func (g *coreNetworksProvider) authorize(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token == "" {
		g.loadToken()
	}
	if g.token != "" && time.Now().Before(g.expires.Add(-30*time.Second)) {
		return g.token, nil
	}
	body, _ := json.Marshal(map[string]string{"login": g.Login, "password": g.Password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.base()+"/auth/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := g.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", fmt.Errorf("could not log in: Core-Networks limits the number of logins and answered 429; wait a few minutes and try again")
	}
	if resp.StatusCode != http.StatusOK {
		return "", g.fail("could not log in", resp.StatusCode, out)
	}
	var t struct {
		Token   string          `json:"token"`
		Expires json.RawMessage `json:"expires"`
	}
	if err := json.Unmarshal(out, &t); err != nil || t.Token == "" {
		return "", fmt.Errorf("could not log in: Core-Networks sent no token")
	}
	secs, _ := strconv.Atoi(strings.Trim(string(t.Expires), `"`))
	if secs <= 0 {
		secs = 300
	}
	g.token, g.expires = t.Token, time.Now().Add(time.Duration(secs)*time.Second)
	g.saveToken()
	return g.token, nil
}

func (g *coreNetworksProvider) fail(what string, status int, body []byte) error {
	b := strings.TrimSpace(string(body))
	if len(b) > 300 {
		b = b[:300] + "..."
	}
	return fmt.Errorf("%s: Core-Networks answered %d: %s", what, status, b)
}

// do sends an authenticated request and returns the status and body. A 401 or a
// 403 (the service answers 403 to a token it does not know) is retried once with
// a fresh token, in case the old one expired early; the new login fails if the
// credentials themselves are wrong.
func (g *coreNetworksProvider) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		tok, err := g.authorize(ctx)
		if err != nil {
			return 0, nil, err
		}
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, g.base()+path, rd)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := g.httpClient().Do(req)
		if err != nil {
			return 0, nil, err
		}
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && attempt == 0 {
			g.forgetToken()
			continue
		}
		return resp.StatusCode, out, nil
	}
}

func cnZonePath(zone string) string {
	return "/dnszones/" + url.PathEscape(strings.TrimSuffix(zone, ".")) + "/records/"
}

func cnZoneNotFound(zone string) error {
	return &contract.Error{Code: contract.CodeZoneNotFound,
		Message: "Core-Networks does not have the zone " + strings.TrimSuffix(zone, ".")}
}

// ListZones lists the zones the account can edit. Slave zones are left out: they
// are copies of a zone held elsewhere.
func (g *coreNetworksProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	status, body, err := g.do(ctx, http.MethodGet, "/dnszones/", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, g.fail("could not list zones", status, body)
	}
	var zs []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &zs); err != nil {
		return nil, fmt.Errorf("could not decode Core-Networks' answer: %w", err)
	}
	var out []libdns.Zone
	for _, z := range zs {
		if z.Type == "" || strings.EqualFold(z.Type, "master") {
			out = append(out, libdns.Zone{Name: strings.TrimSuffix(z.Name, ".") + "."})
		}
	}
	return out, nil
}

func (g *coreNetworksProvider) list(ctx context.Context, zone string) ([]cnRecord, error) {
	status, body, err := g.do(ctx, http.MethodGet, cnZonePath(zone), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, cnZoneNotFound(zone)
	}
	if status != http.StatusOK {
		return nil, g.fail("could not get records", status, body)
	}
	var recs []cnRecord
	if err := json.Unmarshal(body, &recs); err != nil {
		return nil, fmt.Errorf("could not decode Core-Networks' answer: %w", err)
	}
	return recs, nil
}

func (g *coreNetworksProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
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

func (r cnRecord) toLibdns() libdns.Record {
	name := r.Name
	if name == "" {
		name = "@"
	}
	typ := strings.ToUpper(r.Type)
	data := r.Data
	if typ == "TXT" {
		data = cnDecodeTXT(data)
	}
	return libdns.RR{Name: name, Type: typ, TTL: r.ttl(), Data: data}
}

// cnEncodeTXT prepares a TXT value for the API. Text without a quote or a
// backslash is sent as it is: the service keeps it as one string and splits it at
// 255 bytes itself. Anything else is sent as zone-file strings, quoted, escaped
// and split at 255 bytes, which the service serves as written.
func cnEncodeTXT(s string) string {
	if !strings.ContainsAny(s, `"\`) {
		return s
	}
	var parts []string
	for len(s) > 0 || len(parts) == 0 {
		n := len(s)
		if n > 255 {
			n = 255
			for n > 0 && !utf8.RuneStart(s[n]) { // never cut a character in two
				n--
			}
		}
		esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s[:n])
		parts = append(parts, `"`+esc+`"`)
		s = s[n:]
	}
	return strings.Join(parts, " ")
}

// cnDecodeTXT reverses cnEncodeTXT, and reads what someone else entered in zone
// file form (an SPF record in quotes). A value that does not start with a quote is
// returned as it is; so is one that is not a well formed list of quoted strings.
func cnDecodeTXT(s string) string {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, `"`) {
		return s
	}
	var out strings.Builder
	i := 0
	for i < len(t) {
		if t[i] == ' ' || t[i] == '\t' {
			i++
			continue
		}
		if t[i] != '"' {
			return s
		}
		i++
		closed := false
		for i < len(t) {
			c := t[i]
			switch {
			case c == '"':
				closed = true
			case c == '\\' && i+1 < len(t):
				i++
				if d := t[i]; d >= '0' && d <= '9' && i+2 < len(t) && t[i+1] >= '0' && t[i+1] <= '9' && t[i+2] >= '0' && t[i+2] <= '9' {
					n := int(d-'0')*100 + int(t[i+1]-'0')*10 + int(t[i+2]-'0')
					if n > 255 {
						return s
					}
					out.WriteByte(byte(n))
					i += 2
				} else {
					out.WriteByte(d)
				}
			default:
				out.WriteByte(c)
			}
			i++
			if closed {
				break
			}
		}
		if !closed {
			return s
		}
	}
	return out.String()
}

// commit publishes the pending changes of a zone to the name servers.
func (g *coreNetworksProvider) commit(ctx context.Context, zone string) error {
	status, body, err := g.do(ctx, http.MethodPost, cnZonePath(zone)+"commit", nil)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return g.fail("could not commit the changes", status, body)
	}
	return nil
}

// add posts one record.
func (g *coreNetworksProvider) add(ctx context.Context, zone string, rr libdns.RR) error {
	data := rr.Data
	if strings.EqualFold(rr.Type, "TXT") {
		data = cnEncodeTXT(data)
	}
	rec := map[string]any{"name": rr.Name, "type": strings.ToUpper(rr.Type), "data": data}
	if rr.Name == "" {
		rec["name"] = "@"
	}
	if s := int(rr.TTL / time.Second); s > 0 {
		if s < coreNetworksMinTTL {
			s = coreNetworksMinTTL
		}
		rec["ttl"] = s
	}
	status, body, err := g.do(ctx, http.MethodPost, cnZonePath(zone), rec)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return cnZoneNotFound(zone)
	}
	if status/100 != 2 {
		return g.fail("could not add a "+rr.Type+" record", status, body)
	}
	return nil
}

// remove deletes the records equal to rec. rec must have a name, a type and data:
// the API treats every missing field as a wildcard, and an empty body would delete
// the whole zone.
func (g *coreNetworksProvider) remove(ctx context.Context, zone string, rec cnRecord) error {
	if rec.Name == "" || rec.Type == "" || rec.Data == "" {
		return fmt.Errorf("refusing to delete without a name, a type and data")
	}
	status, body, err := g.do(ctx, http.MethodPost, cnZonePath(zone)+"delete",
		map[string]string{"name": rec.Name, "type": rec.Type, "data": rec.Data})
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return g.fail("could not delete a "+rec.Type+" record", status, body)
	}
	return nil
}

// cnSameData compares record data the way DNS does: host names ignoring case and
// a trailing dot.
func cnSameData(typ, a, b string) bool {
	switch strings.ToUpper(typ) {
	case "CNAME", "NS", "MX", "SRV", "PTR":
		f, g := strings.Fields(a), strings.Fields(b)
		if len(f) != len(g) || len(f) == 0 {
			return a == b
		}
		for i := range f {
			x, y := f[i], g[i]
			if i == len(f)-1 {
				x, y = strings.ToLower(strings.TrimSuffix(x, ".")), strings.ToLower(strings.TrimSuffix(y, "."))
			}
			if x != y {
				return false
			}
		}
		return true
	case "A", "AAAA":
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	case "TXT":
		return cnDecodeTXT(a) == cnDecodeTXT(b)
	}
	return a == b
}

func cnName(n string) string {
	if n == "" {
		return "@"
	}
	return strings.ToLower(n)
}

// AppendRecords adds the records; adding one that already exists is not an error
// and creates no duplicate.
func (g *coreNetworksProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) (added []libdns.Record, err error) {
	changed := false
	defer func() { err = g.finish(ctx, zone, changed, err) }()
	for _, r := range recs {
		rr := r.RR()
		if err = g.add(ctx, zone, rr); err != nil {
			return added, err
		}
		changed = true
		added = append(added, rr)
	}
	return added, nil
}

// finish commits when anything was changed, even after a failure part way, so
// that what GetRecords shows is what the name servers serve.
func (g *coreNetworksProvider) finish(ctx context.Context, zone string, changed bool, err error) error {
	if !changed {
		return err
	}
	if cerr := g.commit(context.WithoutCancel(ctx), zone); cerr != nil && err == nil {
		return cerr
	}
	return err
}

// matches lists the existing records that a libdns delete request names: same
// name and type, and the same data and TTL when the request states them.
func matches(existing []cnRecord, rr libdns.RR) []cnRecord {
	var out []cnRecord
	for _, e := range existing {
		if cnName(e.Name) != cnName(rr.Name) || !strings.EqualFold(e.Type, rr.Type) {
			continue
		}
		if rr.Data != "" && !cnSameData(rr.Type, e.Data, rr.Data) {
			continue
		}
		if rr.TTL != 0 && e.ttl() != rr.TTL {
			continue
		}
		out = append(out, e)
	}
	return out
}

// DeleteRecords removes the records that match, resolved against the zone, and
// commits.
func (g *coreNetworksProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) (deleted []libdns.Record, err error) {
	existing, err := g.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	changed := false
	defer func() { err = g.finish(ctx, zone, changed, err) }()
	done := map[string]bool{}
	for _, r := range recs {
		for _, e := range matches(existing, r.RR()) {
			k := cnName(e.Name) + "|" + strings.ToUpper(e.Type) + "|" + e.Data
			if done[k] {
				continue
			}
			done[k] = true
			if err = g.remove(ctx, zone, e); err != nil {
				return deleted, err
			}
			changed = true
			deleted = append(deleted, e.toLibdns())
		}
	}
	return deleted, nil
}

// SetRecords makes the records the only members of their (name, type) sets: the
// API has no update, so the existing members are deleted and the new ones added.
func (g *coreNetworksProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) (set []libdns.Record, err error) {
	existing, err := g.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	changed := false
	defer func() { err = g.finish(ctx, zone, changed, err) }()
	done := map[string]bool{}
	for _, r := range recs {
		rr := r.RR()
		k := cnName(rr.Name) + "|" + strings.ToUpper(rr.Type)
		if done[k] {
			continue
		}
		done[k] = true
		for _, e := range matches(existing, libdns.RR{Name: rr.Name, Type: rr.Type}) {
			if err = g.remove(ctx, zone, e); err != nil {
				return set, err
			}
			changed = true
		}
	}
	for _, r := range recs {
		rr := r.RR()
		if err = g.add(ctx, zone, rr); err != nil {
			return set, err
		}
		changed = true
		set = append(set, rr)
	}
	return set, nil
}
