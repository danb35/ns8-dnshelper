package registry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// fakeGoDaddy is an in-memory GoDaddy Domains API: PUT replaces a record set,
// DELETE removes it, GET lists everything (one page).
type fakeGoDaddy struct {
	mu          sync.Mutex
	sets        map[string][]map[string]any // "TYPE/name" -> records
	tooMany     int                         // answer 429 this many times first
	auth        string
	domains     []string
	domainCalls []string
}

func (f *fakeGoDaddy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	if f.tooMany > 0 {
		f.tooMany--
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if r.URL.Path == "/v1/domains" {
		f.domainCalls = append(f.domainCalls, r.URL.RawQuery)
		names := f.domains
		if m := r.URL.Query().Get("marker"); m != "" {
			for i, n := range names {
				if n == m {
					names = names[i+1:]
					break
				}
			}
		}
		if len(names) > 2 { // a page of two in these tests
			names = names[:2]
		}
		out := []map[string]string{}
		for _, n := range names {
			out = append(out, map[string]string{"domain": n})
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1/domains/example.com/records")
	switch r.Method {
	case http.MethodGet:
		var all []map[string]any
		for k, recs := range f.sets {
			typ, name, _ := strings.Cut(k, "/")
			for _, rec := range recs {
				c := map[string]any{"type": typ, "name": name}
				for a, b := range rec {
					c[a] = b
				}
				all = append(all, c)
			}
		}
		if all == nil {
			all = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(all)
	case http.MethodPut:
		var recs []map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &recs)
		f.sets[strings.TrimPrefix(p, "/")] = recs
	case http.MethodDelete:
		delete(f.sets, strings.TrimPrefix(p, "/"))
		w.WriteHeader(http.StatusNoContent)
	}
}

func newFake(t *testing.T) (*goDaddyProvider, *fakeGoDaddy) {
	f := &fakeGoDaddy{sets: map[string][]map[string]any{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &goDaddyProvider{APIKey: "k", APISecret: "s", baseURL: srv.URL}, f
}

func txt(name, data string) libdns.Record { return libdns.RR{Name: name, Type: "TXT", Data: data} }

func TestGoDaddyAppendKeepsTheRestOfTheSet(t *testing.T) {
	g, f := newFake(t)
	ctx := context.Background()
	if _, err := g.AppendRecords(ctx, "example.com", []libdns.Record{txt("@", "one")}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.AppendRecords(ctx, "example.com", []libdns.Record{txt("@", "two"), txt("@", "one")}); err != nil {
		t.Fatal(err)
	}
	if got := len(f.sets["TXT/@"]); got != 2 {
		t.Fatalf("want both values (no duplicate), got %v", f.sets["TXT/@"])
	}
	if f.auth != "sso-key k:s" {
		t.Fatalf("auth header %q", f.auth)
	}
	if ttl := f.sets["TXT/@"][0]["ttl"]; ttl != float64(600) {
		t.Fatalf("TTL must be raised to 600, got %v", ttl)
	}
}

func TestGoDaddyDeleteRemovesOnlyTheMatch(t *testing.T) {
	g, f := newFake(t)
	ctx := context.Background()
	_, _ = g.AppendRecords(ctx, "example.com", []libdns.Record{txt("@", "one"), txt("@", "two")})
	del, err := g.DeleteRecords(ctx, "example.com", []libdns.Record{txt("@", "one")})
	if err != nil || len(del) != 1 {
		t.Fatalf("%v %v", del, err)
	}
	if recs := f.sets["TXT/@"]; len(recs) != 1 || recs[0]["data"] != "two" {
		t.Fatalf("the other value must stay: %v", recs)
	}
	if _, err := g.DeleteRecords(ctx, "example.com", []libdns.Record{txt("@", "two")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.sets["TXT/@"]; ok {
		t.Fatal("an empty set must be removed")
	}
}

func TestGoDaddySetReplacesTheSet(t *testing.T) {
	g, f := newFake(t)
	ctx := context.Background()
	_, _ = g.AppendRecords(ctx, "example.com", []libdns.Record{txt("@", "one"), txt("@", "two")})
	if _, err := g.SetRecords(ctx, "example.com", []libdns.Record{txt("@", "three")}); err != nil {
		t.Fatal(err)
	}
	if recs := f.sets["TXT/@"]; len(recs) != 1 || recs[0]["data"] != "three" {
		t.Fatalf("%v", recs)
	}
}

func TestGoDaddyMXAndSRVUseSeparateFields(t *testing.T) {
	g, f := newFake(t)
	ctx := context.Background()
	_, err := g.AppendRecords(ctx, "example.com", []libdns.Record{
		libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.net"},
		libdns.RR{Name: "_sip._tcp", Type: "SRV", Data: "10 5 5060 sip.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mx := f.sets["MX/@"][0]
	if mx["data"] != "mail.example.net" || mx["priority"] != float64(10) {
		t.Fatalf("%v", mx)
	}
	srv := f.sets["SRV/_sip._tcp"][0]
	if srv["service"] != "_sip" || srv["protocol"] != "_tcp" || srv["port"] != float64(5060) || srv["weight"] != float64(5) || srv["data"] != "sip.example.net" {
		t.Fatalf("%v", srv)
	}
	recs, err := g.GetRecords(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range recs {
		got[r.RR().Type] = r.RR().Data
	}
	if got["MX"] != "10 mail.example.net" || got["SRV"] != "10 5 5060 sip.example.net" {
		t.Fatalf("records must read back in libdns form: %v", got)
	}
	if _, err := g.AppendRecords(ctx, "example.com", []libdns.Record{libdns.RR{Name: "x", Type: "SRV", Data: "10 5 5060 t"}}); err == nil {
		t.Fatal("an SRV name without _service._protocol must be refused")
	}
}

func TestGoDaddyRetriesWhenRateLimited(t *testing.T) {
	g, f := newFake(t)
	f.tooMany = 1
	if _, err := g.GetRecords(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestGoDaddyPersonalAccessTokenIsSentAsBearer(t *testing.T) {
	g, f := newFake(t)
	g.APIToken, g.APIKey, g.APISecret = "gd_pat_x", "", ""
	if _, err := g.GetRecords(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if f.auth != "Bearer gd_pat_x" {
		t.Fatalf("auth header %q", f.auth)
	}
}

func TestGoDaddyListZonesFollowsTheMarker(t *testing.T) {
	g, f := newFake(t)
	g.APIToken = "t"
	f.domains = []string{"a.example", "b.example", "c.example"}
	g.domainPage = 2 // the fake serves two per page
	zones, err := g.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 3 || zones[0].Name != "a.example." || zones[2].Name != "c.example." {
		t.Fatalf("all pages must be read: %v", zones)
	}
	if len(f.domainCalls) != 2 || !strings.Contains(f.domainCalls[1], "marker=b.example") {
		t.Fatalf("the second page must continue after the last domain: %v", f.domainCalls)
	}
	if !strings.Contains(f.domainCalls[0], "statuses=ACTIVE") {
		t.Fatalf("only active domains must be listed: %v", f.domainCalls)
	}
}

func TestGoDaddyLegacyKeyIsReportedAsUnableToListZones(t *testing.T) {
	g, _ := newFake(t) // the fake is built with a legacy key
	_, err := g.ListZones(context.Background())
	var ce *contract.Error
	if !errors.As(err, &ce) || ce.Code != contract.CodeUnsupported {
		t.Fatalf("want an unsupported error, got %v", err)
	}
}

func TestGoDaddyCredentialCheck(t *testing.T) {
	def, _ := Get("godaddy")
	ok := []map[string]string{{"api_token": "t"}, {"api_key": "k", "api_secret": "s"}}
	bad := []map[string]string{{}, {"api_key": "k"}, {"api_secret": "s"}, {"api_token": "t", "api_key": "k", "api_secret": "s"}}
	for _, c := range ok {
		if _, err := def.Check(c); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	for _, c := range bad {
		if _, err := def.Check(c); err == nil {
			t.Errorf("%v must be refused", c)
		}
	}
}
