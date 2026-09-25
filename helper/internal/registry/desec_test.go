package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// fakeDeSEC is an in-memory deSEC API holding example.com (minimum TTL 900).
// Like the real one it takes a bulk PUT of record sets, refuses a TTL under
// the minimum or a subname in upper case (rejecting the whole request),
// removes a set written with no records, answers 401 to a wrong token and 404
// to an unknown domain, and pages lists with a cursor.
type fakeDeSEC struct {
	mu       sync.Mutex
	url      string
	sets     map[string]dsRRset // "subname/TYPE"
	puts     [][]byte
	pageSize int // rrsets per page; 0 means no paging
	throttle int // answer 429 this many times first
	auth     string
}

func (f *fakeDeSEC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	answer := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if f.throttle > 0 {
		f.throttle--
		w.Header().Set("Retry-After", "1")
		answer(http.StatusTooManyRequests, map[string]string{"detail": "Request was throttled."})
		return
	}
	if f.auth != "Token tok" {
		answer(http.StatusUnauthorized, map[string]string{"detail": "Invalid token."})
		return
	}
	switch p := r.URL.Path; {
	case p == "/domains/":
		answer(http.StatusOK, []map[string]any{{"name": "example.com", "minimum_ttl": 900}})
	case !strings.HasPrefix(p, "/domains/example.com/"):
		answer(http.StatusNotFound, map[string]string{"detail": "Not found."})
	case p == "/domains/example.com/":
		answer(http.StatusOK, map[string]any{"name": "example.com", "minimum_ttl": 900})
	case p == "/domains/example.com/rrsets/" && r.Method == http.MethodGet:
		var keys []string
		for k := range f.sets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		all := []dsRRset{}
		for _, k := range keys {
			all = append(all, f.sets[k])
		}
		if f.pageSize > 0 {
			var start int
			if c := r.URL.Query().Get("cursor"); c != "" {
				start = int(c[0] - '0')
			}
			end := start + f.pageSize
			if end < len(all) {
				w.Header().Set("Link", `<`+f.url+`/domains/example.com/rrsets/?cursor=>; rel="first", <`+f.url+`/domains/example.com/rrsets/?cursor=`+string(rune('0'+end))+`>; rel="next"`)
			} else {
				end = len(all)
			}
			all = all[start:end]
		}
		answer(http.StatusOK, all)
	case p == "/domains/example.com/rrsets/" && r.Method == http.MethodPut:
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		f.puts = append(f.puts, raw)
		var in []dsRRset
		_ = json.Unmarshal(raw, &in)
		for _, s := range in {
			if s.TTL < 900 || s.TTL > 86400 {
				answer(http.StatusBadRequest, []map[string][]string{{"ttl": {"out of range"}}})
				return
			}
			if s.Subname != strings.ToLower(s.Subname) {
				answer(http.StatusBadRequest, []map[string][]string{{"subname": {"not lowercase"}}})
				return
			}
		}
		for _, s := range in {
			k := s.Subname + "/" + s.Type
			if len(s.Records) == 0 {
				delete(f.sets, k)
			} else {
				f.sets[k] = s
			}
		}
		answer(http.StatusOK, in)
	default:
		answer(http.StatusNotFound, map[string]string{"detail": "Not found."})
	}
}

func newFakeDeSEC(t *testing.T) (*fakeDeSEC, *desecProvider) {
	f := &fakeDeSEC{sets: map[string]dsRRset{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f, &desecProvider{Token: "tok", baseURL: srv.URL}
}

func dsData(t *testing.T, p *desecProvider) []string {
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

// Issue #19: the zero priority and weight of an SRV record must be in the
// bytes sent. deSEC takes the whole value as one string, so they are.
func TestDeSECZeroSRVSentExplicitly(t *testing.T) {
	f, p := newFakeDeSEC(t)
	srv := libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net."}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	if got := string(f.puts[0]); got != `[{"subname":"_autodiscover._tcp","type":"SRV","ttl":3600,"records":["0 0 443 mail.example.net."]}]` {
		t.Errorf("body %s", got)
	}
	if f.auth != "Token tok" {
		t.Errorf("auth %q", f.auth)
	}
	if got := dsData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
}

func TestDeSECRecordForms(t *testing.T) {
	f, p := newFakeDeSEC(t)
	ctx := context.Background()
	long := strings.Repeat("k", 400)
	in := []libdns.Record{
		libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.net", TTL: 60e9},
		libdns.RR{Name: "WWW", Type: "CNAME", Data: "target.example.net"},
		libdns.RR{Name: "@", Type: "TXT", Data: `v=spf1 "quoted" -all`},
		libdns.RR{Name: "dkim._domainkey", Type: "TXT", Data: long},
	}
	if _, err := p.AppendRecords(ctx, "example.com.", in); err != nil {
		t.Fatal(err)
	}
	if len(f.puts) != 1 {
		t.Fatalf("one bulk request expected, got %d", len(f.puts))
	}
	if s := f.sets["/MX"]; s.TTL != 900 || s.Records[0] != "10 mail.example.net." {
		t.Errorf("MX %+v (TTL raised to the domain's minimum, target made absolute)", s)
	}
	if _, ok := f.sets["www/CNAME"]; !ok {
		t.Errorf("subname must be sent in lower case: %v", f.sets)
	}
	if s := f.sets["dkim._domainkey/TXT"]; !strings.Contains(s.Records[0], `" "`) {
		t.Errorf("long TXT must be sent as several strings: %v", s.Records)
	}
	got := strings.Join(dsData(t, p), "\n")
	for _, want := range []string{"@ MX 10 mail.example.net.", "www CNAME target.example.net.", `@ TXT v=spf1 "quoted" -all`, "dkim._domainkey TXT " + long} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestDeSECAppendDeleteAndSet(t *testing.T) {
	f, p := newFakeDeSEC(t)
	ctx := context.Background()
	txt := func(d string) libdns.Record { return libdns.RR{Name: "x", Type: "TXT", Data: d} }
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("b"),
		libdns.RR{Name: "y", Type: "AAAA", Data: "2001:DB8:0:0::1", TTL: 7200e9}}); err != nil {
		t.Fatal(err)
	}
	// deSEC stores addresses in their short form; the fake does not, so do it here.
	f.sets["y/AAAA"] = dsRRset{Subname: "y", Type: "AAAA", TTL: 7200, Records: []string{"2001:db8::1"}}
	n := len(f.puts)
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{txt("a")}); err != nil || len(f.puts) != n {
		t.Fatalf("appending a value already there must write nothing: %v, %d requests", err, len(f.puts)-n)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{txt("b"), libdns.RR{Name: "y", Type: "AAAA", Data: "2001:DB8::0:1"}}); err != nil || len(del) != 2 {
		t.Fatalf("exact delete: %v %v", del, err)
	}
	if got := string(f.puts[len(f.puts)-1]); got != `[{"subname":"x","type":"TXT","ttl":3600,"records":["\"a\""]},{"subname":"y","type":"AAAA","ttl":7200,"records":[]}]` {
		t.Errorf("delete body %s", got)
	}
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{txt("c"), txt("d")}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dsData(t, p), ","); got != "x TXT c,x TXT d" {
		t.Fatalf("after set: %s", got)
	}
}

func TestDeSECPagingRetryAndErrors(t *testing.T) {
	f, p := newFakeDeSEC(t)
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		f.sets[n+"/A"] = dsRRset{Subname: n, Type: "A", TTL: 3600, Records: []string{"192.0.2.1"}}
	}
	f.pageSize = 2
	f.throttle = 1
	if got := dsData(t, p); len(got) != 5 {
		t.Fatalf("paged read: %v", got)
	}
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com." {
		t.Fatalf("zones %v %v", zones, err)
	}
	var ce *contract.Error
	if _, err := p.GetRecords(ctx, "other.org."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("unknown zone: %v", err)
	}
	if _, err := p.AppendRecords(ctx, "other.org.", []libdns.Record{libdns.RR{Name: "x", Type: "A", Data: "192.0.2.1"}}); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("unknown zone, write: %v", err)
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "A", Data: "192.0.2.1", TTL: 3e12}}); err != nil {
		t.Fatalf("a TTL over the maximum is lowered: %v", err)
	}
	p.Token = "wrong"
	if _, err := p.GetRecords(ctx, "example.com."); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed {
		t.Fatalf("bad token: %v", err)
	}
	if err := p.fail("could not write records", 400, []byte(`[{"ttl":["too low"]}]`)); err.Error() != `could not write records: deSEC answered 400: [{"ttl":["too low"]}]` {
		t.Fatalf("got %v", err)
	}
}

// The next-page link must stay on deSEC's API, so the token is never sent
// elsewhere.
func TestDeSECRefusesForeignNextLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://elsewhere.example/steal?cursor=1>; rel="next"`)
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)
	p := &desecProvider{Token: "tok", baseURL: srv.URL}
	if _, err := p.GetRecords(context.Background(), "example.com."); err == nil || !strings.Contains(err.Error(), "unexpected next page") {
		t.Fatalf("got %v", err)
	}
}
