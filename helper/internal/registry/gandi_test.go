package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// fakeGandi is an in-memory LiveDNS API holding example.com. Like the real
// one it stores record sets, answers 403 to a wrong token and 404 to an
// unknown domain or set, and pages lists with per_page and page.
type fakeGandi struct {
	mu     sync.Mutex
	sets   map[string]gnRRset // "name/TYPE", name lower-cased
	bodies [][]byte           // raw PUT bodies
	calls  []string           // method and path of each write
	auth   string
}

func (f *fakeGandi) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	answer := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if f.auth != "Bearer tok" {
		answer(http.StatusForbidden, map[string]any{"object": "HTTPForbidden", "cause": "Forbidden", "code": 403, "message": "Access was denied to this resource."})
		return
	}
	page := func(all []any) []any {
		size, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		n, _ := strconv.Atoi(r.URL.Query().Get("page"))
		lo, hi := (n-1)*size, n*size
		if lo > len(all) {
			lo = len(all)
		}
		if hi > len(all) {
			hi = len(all)
		}
		return all[lo:hi]
	}
	p := strings.TrimPrefix(r.URL.Path, "/domains")
	if p == "" {
		answer(http.StatusOK, page([]any{map[string]string{"fqdn": "example.com"}, map[string]string{"fqdn": "example.org"}, map[string]string{"fqdn": "example.net"}}))
		return
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if parts[0] != "example.com" || len(parts) < 2 || parts[1] != "records" {
		answer(http.StatusNotFound, map[string]any{"object": "HTTPNotFound", "code": 404, "message": "The resource could not be found."})
		return
	}
	if len(parts) == 2 {
		var keys []string
		for k := range f.sets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		all := []any{}
		for _, k := range keys {
			all = append(all, f.sets[k])
		}
		answer(http.StatusOK, page(all))
		return
	}
	key := strings.ToLower(parts[2]) + "/" + parts[3]
	switch r.Method {
	case http.MethodPut:
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		f.bodies = append(f.bodies, raw)
		f.calls = append(f.calls, "PUT "+key)
		var s gnRRset
		_ = json.Unmarshal(raw, &s)
		if s.TTL != 0 && (s.TTL < 300 || s.TTL > 2592000) {
			answer(http.StatusBadRequest, map[string]any{"status": "error", "errors": []map[string]string{{"location": "body", "name": "rrset_ttl", "description": "out of range"}}})
			return
		}
		if s.TTL == 0 {
			s.TTL = 10800
		}
		s.Name, s.Type = parts[2], parts[3]
		f.sets[key] = s
		answer(http.StatusCreated, map[string]string{"message": "DNS Record Created"})
	case http.MethodDelete:
		f.calls = append(f.calls, "DELETE "+key)
		if _, ok := f.sets[key]; !ok {
			answer(http.StatusNotFound, map[string]any{"object": "dns-record", "code": 404, "message": "Can't find the DNS record"})
			return
		}
		delete(f.sets, key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func newFakeGandi(t *testing.T) (*fakeGandi, *gandiProvider) {
	f := &fakeGandi{sets: map[string]gnRRset{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &gandiProvider{Token: "tok", baseURL: srv.URL, perPage: 2}
}

func gnData(t *testing.T, p *gandiProvider) []string {
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
// bytes sent. LiveDNS takes the whole value as one string, so they are.
func TestGandiZeroSRVSentExplicitly(t *testing.T) {
	f, p := newFakeGandi(t)
	srv := libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net."}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	if got := string(f.bodies[0]); got != `{"rrset_values":["0 0 443 mail.example.net."]}` {
		t.Errorf("body %s", got)
	}
	if f.calls[0] != "PUT _autodiscover._tcp/SRV" || f.auth != "Bearer tok" {
		t.Errorf("calls %v auth %q", f.calls, f.auth)
	}
	if got := gnData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
}

func TestGandiTXTQuotingAndChunking(t *testing.T) {
	long := strings.Repeat("a", 250) + `"\` + strings.Repeat("é", 10) + strings.Repeat("b", 300)
	for _, tc := range []struct{ in, sent string }{
		{`v=spf1 -all`, `"v=spf1 -all"`},
		{`a " b \ c`, `"a \" b \\ c"`},
		{"", `""`},
	} {
		if got := gnQuoteTXT(tc.in); got != tc.sent {
			t.Errorf("quote %q: %s, want %s", tc.in, got, tc.sent)
		}
		if got := gnUnquoteTXT(tc.sent); got != tc.in {
			t.Errorf("unquote %s: %q", tc.sent, got)
		}
	}
	q := gnQuoteTXT(long)
	if gnUnquoteTXT(q) != long {
		t.Fatal("long value does not round-trip")
	}
	// Each string holds at most 255 bytes once unescaped, and no character is cut.
	for _, part := range strings.Split(q, `" "`) {
		u := gnUnquoteTXT(`"` + strings.Trim(part, `"`) + `"`)
		if len(u) > 255 || strings.ContainsRune(u, '�') {
			t.Fatalf("chunk of %d bytes: %q", len(u), u)
		}
	}
	// Gandi's own split and a \DDD escape.
	if got := gnUnquoteTXT(`"abc" "def\034g\\h"`); got != `abcdef"g\h` {
		t.Fatalf("got %q", got)
	}
	if got := gnUnquoteTXT(`not quoted`); got != "not quoted" {
		t.Fatalf("got %q", got)
	}
}

func TestGandiRecordForms(t *testing.T) {
	f, p := newFakeGandi(t)
	ctx := context.Background()
	in := []libdns.Record{
		libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.net", TTL: 60e9},
		libdns.RR{Name: "www", Type: "CNAME", Data: "target.example.net"},
		libdns.RR{Name: "@", Type: "TXT", Data: `v=spf1 "quoted" -all`},
	}
	if _, err := p.AppendRecords(ctx, "example.com.", in); err != nil {
		t.Fatal(err)
	}
	if s := f.sets["@/MX"]; s.TTL != 300 || s.Values[0] != "10 mail.example.net." {
		t.Errorf("MX %+v (TTL raised to 300, target made absolute)", s)
	}
	if s := f.sets["@/TXT"]; s.Values[0] != `"v=spf1 \"quoted\" -all"` || s.TTL != 10800 {
		t.Errorf("TXT %+v", s)
	}
	// Values Gandi holds relative to the zone are read back absolute.
	f.sets["web/CNAME"] = gnRRset{Name: "web", Type: "CNAME", TTL: 300, Values: []string{"www"}}
	f.sets["_x._tcp/SRV"] = gnRRset{Name: "_x._tcp", Type: "SRV", TTL: 300, Values: []string{"0 0 0   ."}}
	got := strings.Join(gnData(t, p), "\n")
	for _, want := range []string{"@ MX 10 mail.example.net.", "www CNAME target.example.net.", `@ TXT v=spf1 "quoted" -all`,
		"web CNAME www.example.com.", "_x._tcp SRV 0 0 0 ."} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "SRV", Data: "0 443 t."}}); err == nil {
		t.Error("a malformed SRV value must be refused")
	}
}

func TestGandiAppendDeleteAndSet(t *testing.T) {
	f, p := newFakeGandi(t)
	ctx := context.Background()
	txt := func(d string) libdns.Record { return libdns.RR{Name: "x", Type: "TXT", Data: d} }
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("b")}); err != nil {
		t.Fatal(err)
	}
	// Appending keeps the values already there and does not duplicate one.
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{txt("c"), txt("a"), libdns.RR{Name: "y", Type: "TXT", Data: "other", TTL: 600e9}}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(gnData(t, p), ","); got != "x TXT a,x TXT b,x TXT c,y TXT other" {
		t.Fatalf("after append: %s", got)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{txt("A")}); err != nil || len(del) != 0 {
		t.Fatalf("TXT values are compared exactly: %v %v", del, err)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{txt("b")}); err != nil || len(del) != 1 {
		t.Fatalf("exact delete: %v %v", del, err)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "y", Type: "TXT", Data: "other", TTL: 300e9}}); err != nil || len(del) != 0 {
		t.Fatalf("delete with another TTL: %v %v", del, err)
	}
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("d")}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(gnData(t, p), ","); got != "x TXT a,x TXT d,y TXT other" {
		t.Fatalf("after set: %s", got)
	}
	f.calls = nil
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x"}}); err != nil || len(del) != 2 {
		t.Fatalf("name-only delete: %v %v", del, err)
	}
	if strings.Join(f.calls, ",") != "DELETE x/TXT" {
		t.Fatalf("an emptied set must be deleted: %v", f.calls)
	}
	if got := strings.Join(gnData(t, p), ","); got != "y TXT other" {
		t.Fatalf("after delete: %s", got)
	}
}

func TestGandiZonesAndErrors(t *testing.T) {
	_, p := newFakeGandi(t)
	ctx := context.Background()
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 3 || zones[2].Name != "example.net." {
		t.Fatalf("zones (over two pages) %v %v", zones, err)
	}
	var ce *contract.Error
	if _, err := p.GetRecords(ctx, "other.org."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("unknown zone: %v", err)
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "A", Data: "192.0.2.1", TTL: 3e12}}); err != nil {
		t.Fatalf("a TTL over the maximum is lowered: %v", err)
	}
	p.Token = "wrong"
	if _, err := p.GetRecords(ctx, "example.com."); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := p.ListZones(ctx); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed {
		t.Fatalf("bad token, zone list: %v", err)
	}
	err = p.fail("could not write TXT records", 400, []byte(`{"status":"error","errors":[{"location":"body","name":"rrset_values","description":"bad value"}]}`))
	if err.Error() != "could not write TXT records: Gandi answered 400: rrset_values: bad value" {
		t.Fatalf("got %v", err)
	}
}
