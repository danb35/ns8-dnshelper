package registry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// fakeOVH is an in-memory OVHcloud API holding example.com. Like the real one
// it lists record IDs only, stores names in lower case, quotes a TXT target
// sent as plain text, raises a TTL under 60, refuses an underscore in an MX
// name, and answers 404 for a zone the account does not have. It accepts a
// bearer token from its token endpoint or a signed application-key request.
type fakeOVH struct {
	mu        sync.Mutex
	recs      map[int64]ovhRecord
	nextID    int64
	posts     [][]byte
	refreshes int
	tokens    int
	srvURL    string
}

func (f *fakeOVH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	answer := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch r.URL.Path {
	case "/token":
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "EU.id" || r.Form.Get("client_secret") != "sec" || r.Form.Get("grant_type") != "client_credentials" {
			answer(http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "bad client credentials"})
			return
		}
		f.tokens++
		answer(http.StatusOK, map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
		return
	case "/auth/time":
		_, _ = w.Write([]byte("1000000000"))
		return
	}
	body, _ := io.ReadAll(r.Body)
	if app := r.Header.Get("X-Ovh-Application"); app != "" {
		ts, _ := strconv.ParseInt(r.Header.Get("X-Ovh-Timestamp"), 10, 64)
		want := ovhSignature("asec", "ck", r.Method, f.srvURL+r.URL.RequestURI(), body, ts)
		if app != "ak" || r.Header.Get("X-Ovh-Consumer") != "ck" || r.Header.Get("X-Ovh-Signature") != want || ts != 1000000000 {
			answer(http.StatusForbidden, map[string]string{"class": "Client::Forbidden", "message": "Invalid signature"})
			return
		}
	} else if r.Header.Get("Authorization") != "Bearer tok" {
		answer(http.StatusUnauthorized, map[string]string{"class": "Client::Unauthorized", "message": "Invalid credentials"})
		return
	}
	const zp = "/domain/zone/example.com"
	switch p := r.URL.Path; {
	case p == "/domain/zone":
		answer(http.StatusOK, []string{"example.com"})
	case !strings.HasPrefix(p, zp+"/"):
		answer(http.StatusNotFound, map[string]string{"class": "Client::NotFound", "message": "This service does not exist"})
	case p == zp+"/refresh":
		f.refreshes++
		answer(http.StatusOK, nil)
	case p == zp+"/record" && r.Method == http.MethodGet:
		sub, filtered := r.URL.Query()["subDomain"]
		ids := []int64{}
		for id, rec := range f.recs {
			if !filtered || strings.EqualFold(rec.SubDomain, sub[0]) {
				ids = append(ids, id)
			}
		}
		answer(http.StatusOK, ids)
	case p == zp+"/record" && r.Method == http.MethodPost:
		f.posts = append(f.posts, body)
		var rec ovhRecord
		_ = json.Unmarshal(body, &rec)
		if rec.FieldType == "MX" && strings.Contains(rec.SubDomain, "_") {
			answer(http.StatusBadRequest, map[string]string{"class": "Client::BadRequest", "message": "Invalid domain name, underscore not allowed"})
			return
		}
		f.nextID++
		rec.ID = f.nextID
		rec.SubDomain = strings.ToLower(rec.SubDomain)
		if rec.TTL != 0 && rec.TTL < 60 {
			rec.TTL = 60
		}
		if rec.FieldType == "TXT" && !strings.HasPrefix(rec.Target, `"`) {
			rec.Target = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(rec.Target) + `"`
		}
		f.recs[rec.ID] = rec
		answer(http.StatusOK, rec)
	case strings.HasPrefix(p, zp+"/record/"):
		id, _ := strconv.ParseInt(p[len(zp+"/record/"):], 10, 64)
		rec, ok := f.recs[id]
		if !ok {
			answer(http.StatusNotFound, map[string]string{"class": "Client::NotFound", "message": "The requested object (id = " + strconv.FormatInt(id, 10) + ") does not exist"})
			return
		}
		if r.Method == http.MethodDelete {
			delete(f.recs, id)
			answer(http.StatusOK, nil)
			return
		}
		answer(http.StatusOK, rec)
	default:
		answer(http.StatusNotFound, map[string]string{"class": "Client::NotFound", "message": "not found"})
	}
}

func newFakeOVH(t *testing.T) (*fakeOVH, *ovhProvider) {
	f := &fakeOVH{recs: map[int64]ovhRecord{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.srvURL = srv.URL
	return f, &ovhProvider{Endpoint: "ovh-eu", ClientID: "EU.id", ClientSecret: "sec", baseURL: srv.URL, tokenURL: srv.URL + "/token"}
}

func ovhData(t *testing.T, p *ovhProvider) []string {
	t.Helper()
	recs, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		rr := r.RR()
		out = append(out, rr.Name+" "+rr.Type+" "+rr.Data)
	}
	return out
}

// Issue #19: OVH takes an SRV value as one string, so a zero priority and
// weight must be in it.
func TestOVHZeroSRVSentExplicitly(t *testing.T) {
	f, p := newFakeOVH(t)
	srv := libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net"}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	if got := string(f.posts[0]); got != `{"fieldType":"SRV","subDomain":"_autodiscover._tcp","target":"0 0 443 mail.example.net."}` {
		t.Errorf("body %s", got)
	}
	if got := ovhData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
	if f.refreshes != 1 || f.tokens != 1 {
		t.Errorf("refreshes %d, tokens %d: want one of each", f.refreshes, f.tokens)
	}
}

func TestOVHRecordForms(t *testing.T) {
	f, p := newFakeOVH(t)
	ctx := context.Background()
	long := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 400)
	in := []libdns.Record{
		libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.net", TTL: 30 * time.Second},
		libdns.RR{Name: "WWW", Type: "CNAME", Data: "target.example.net."},
		libdns.RR{Name: "@", Type: "TXT", Data: `say "hi" \ café`},
		libdns.RR{Name: "sel._domainkey", Type: "TXT", Data: long},
		libdns.RR{Name: "v6", Type: "AAAA", Data: "2001:db8::1"},
	}
	if _, err := p.AppendRecords(ctx, "example.com.", in); err != nil {
		t.Fatal(err)
	}
	var sent []ovhRecord
	for _, b := range f.posts {
		var r ovhRecord
		_ = json.Unmarshal(b, &r)
		sent = append(sent, r)
	}
	if s := sent[0]; s.SubDomain != "" || s.Target != "10 mail.example.net." || s.TTL != 60 {
		t.Errorf("MX %+v (apex is \"\", target gets a final dot, TTL raised to 60)", s)
	}
	if s := sent[1]; s.SubDomain != "www" {
		t.Errorf("names are sent relative, in lower case: %+v", s)
	}
	if s := sent[2]; s.Target != `"say \"hi\" \\ café"` {
		t.Errorf("TXT must be sent quoted, non-ASCII as it is: %q", s.Target)
	}
	if s := sent[3]; !strings.HasPrefix(s.Target, `"v=DKIM1`) || !strings.Contains(s.Target, `" "`) {
		t.Errorf("a long TXT must be sent in 255-byte strings: %q", s.Target)
	}
	if f.refreshes != 1 {
		t.Errorf("one refresh for the whole append, got %d", f.refreshes)
	}
	got := strings.Join(ovhData(t, p), "\n")
	for _, want := range []string{"@ MX 10 mail.example.net.", "www CNAME target.example.net.", `@ TXT say "hi" \ café`, "sel._domainkey TXT " + long, "v6 AAAA 2001:db8::1"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

// Records made in OVH's web interface: SPF/DKIM/DMARC types, unquoted values,
// targets relative to the zone.
func TestOVHReadsWebInterfaceRecords(t *testing.T) {
	f, p := newFakeOVH(t)
	f.recs[1] = ovhRecord{ID: 1, FieldType: "SPF", SubDomain: "", Target: "v=spf1 include:mx.ovh.com ~all", TTL: 500}
	f.recs[2] = ovhRecord{ID: 2, FieldType: "MX", SubDomain: "", Target: "5 mx"}
	f.recs[3] = ovhRecord{ID: 3, FieldType: "TXT", SubDomain: "", Target: `"1|example.org"`}
	got := strings.Join(ovhData(t, p), "\n")
	for _, want := range []string{"@ TXT v=spf1 include:mx.ovh.com ~all", "@ MX 5 mx.example.com.", "@ TXT 1|example.org"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	// Replacing the SPF value deletes the web interface's SPF record.
	ctx := context.Background()
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{
		libdns.RR{Name: "@", Type: "TXT", Data: "1|example.org"},
		libdns.RR{Name: "@", Type: "TXT", Data: "v=spf1 -all"},
	}); err != nil {
		t.Fatal(err)
	}
	got = strings.Join(ovhData(t, p), "\n")
	if strings.Contains(got, "mx.ovh.com") || !strings.Contains(got, "@ TXT v=spf1 -all") || !strings.Contains(got, "@ TXT 1|example.org") || !strings.Contains(got, "@ MX") {
		t.Errorf("after set:\n%s", got)
	}
	if _, ok := f.recs[3]; !ok {
		t.Errorf("an equal record must be left alone")
	}
}

func TestOVHDeleteAndSet(t *testing.T) {
	f, p := newFakeOVH(t)
	ctx := context.Background()
	f.recs[100] = ovhRecord{ID: 100, FieldType: "TXT", SubDomain: "other", Target: `"keep"`}
	txt := func(d string) libdns.Record {
		return libdns.RR{Name: "x", Type: "TXT", Data: d, TTL: 300 * time.Second}
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("b"), txt("c")}); err != nil {
		t.Fatal(err)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{txt("b")}); err != nil || len(del) != 1 {
		t.Fatalf("exact delete: %v %v", del, err)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{txt("nope")}); err != nil || len(del) != 0 {
		t.Fatalf("inexact delete: %v %v", del, err)
	}
	refreshes := f.refreshes
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("d")}); err != nil {
		t.Fatal(err)
	}
	if f.refreshes != refreshes+1 {
		t.Errorf("set must refresh once")
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x"}}); err != nil || len(del) != 2 {
		t.Fatalf("name-only delete: %v %v", del, err)
	}
	if len(f.recs) != 1 || f.recs[100].Target != `"keep"` {
		t.Fatalf("other names must be left alone: %+v", f.recs)
	}
	refreshes = f.refreshes
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "other", Type: "TXT", Data: "keep"}}); err != nil {
		t.Fatal(err)
	}
	if f.refreshes != refreshes {
		t.Errorf("a set that changes nothing must not refresh")
	}
}

func TestOVHErrors(t *testing.T) {
	f, p := newFakeOVH(t)
	ctx := context.Background()
	var ce *contract.Error
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "_m", Type: "MX", Data: "0 mx.example.net."}}); err == nil || !strings.Contains(err.Error(), "underscore not allowed") {
		t.Fatalf("OVH's message must be passed on: %v", err)
	}
	if f.refreshes != 0 {
		t.Errorf("nothing changed, nothing to refresh")
	}
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com." {
		t.Fatalf("zones: %v %v", zones, err)
	}
	if _, err := p.GetRecords(ctx, "other.org."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("unknown zone: %v", err)
	}
	bad := &ovhProvider{ClientID: "EU.id", ClientSecret: "wrong-secret", baseURL: p.baseURL, tokenURL: p.tokenURL}
	_, err = bad.GetRecords(ctx, "example.com.")
	if !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed || strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("bad secret: %v", err)
	}
	err = p.fail("x", http.StatusForbidden, []byte(`{"class":"Client::Forbidden","message":"User not granted for this request"}`))
	if !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed || !strings.Contains(ce.Message, "IAM policy") {
		t.Fatalf("403: %v", err)
	}
}

// The older login: each request signed with the application secret and
// consumer key, at OVH's time rather than the local clock.
func TestOVHApplicationKeySignature(t *testing.T) {
	f, p := newFakeOVH(t)
	app := &ovhProvider{AppKey: "ak", AppSecret: "asec", ConsumerKey: "ck", baseURL: p.baseURL,
		now: func() time.Time { return time.Unix(1000000000+3600, 0) }}
	ctx := context.Background()
	if _, err := app.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "TXT", Data: "signed"}}); err != nil {
		t.Fatal(err)
	}
	if got := ovhData(t, app); len(got) != 1 || got[0] != "x TXT signed" {
		t.Fatalf("read back %v", got)
	}
	if f.tokens != 0 {
		t.Errorf("no OAuth2 token for an application key")
	}
	// Known answer, computed independently:
	// printf '%s' 'asec+ck+GET+https://eu.api.ovh.com/1.0/domain/zone++1000000000' | sha1sum
	if got := ovhSignature("asec", "ck", "GET", "https://eu.api.ovh.com/1.0/domain/zone", nil, 1000000000); got != "$1$"+ovhKnownSig {
		t.Errorf("signature %s", got)
	}
	app.AppSecret = "wrong"
	var ce *contract.Error
	if _, err := app.GetRecords(ctx, "example.com."); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed {
		t.Fatalf("bad signature: %v", err)
	}
}

func TestOVHVerify(t *testing.T) {
	for _, c := range []struct {
		cred map[string]string
		ok   bool
	}{
		{map[string]string{"endpoint": "ovh-eu", "client_id": "a", "client_secret": "b"}, true},
		{map[string]string{"endpoint": "ovh-ca", "application_key": "a", "application_secret": "b", "consumer_key": "c"}, true},
		{map[string]string{"endpoint": "ovh-xx", "client_id": "a", "client_secret": "b"}, false},
		{map[string]string{"endpoint": "ovh-eu", "client_id": "a"}, false},
		{map[string]string{"endpoint": "ovh-eu", "client_id": "a", "client_secret": "b", "consumer_key": "c"}, false},
		{map[string]string{"endpoint": "ovh-eu", "application_key": "a", "application_secret": "b"}, false},
		{map[string]string{"endpoint": "ovh-eu"}, false},
	} {
		if msg := ovhVerify(c.cred); (msg == "") != c.ok {
			t.Errorf("%v: %q", c.cred, msg)
		}
	}
	d, _ := Get("ovh")
	cred, err := d.Check(map[string]string{"client_id": "a", "client_secret": "b"})
	if err != nil || cred["endpoint"] != "ovh-eu" {
		t.Fatalf("endpoint defaults to ovh-eu: %v %v", cred, err)
	}
}

const ovhKnownSig = "376845036822bac26a7fd66554543158e95a10c3"
