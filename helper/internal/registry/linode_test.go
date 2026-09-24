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

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// fakeLinode is an in-memory Linode Domains API holding example.com (ID 7).
// Like the real API it names an SRV record after its service and protocol,
// ignoring any name sent, and returns targets without the final dot.
type fakeLinode struct {
	mu      sync.Mutex
	recs    []map[string]any
	nextID  int
	bodies  []string // raw POST bodies
	auth    string
	domains []lnDomain
	forbid  bool // answer 403 to the domain list
}

func (f *fakeLinode) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	per, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	list := func(items []any) {
		lo, hi := min((page-1)*per, len(items)), min(page*per, len(items))
		pages := max((len(items)+per-1)/per, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": items[lo:hi], "page": page, "pages": pages})
	}
	if r.URL.Path == "/v4/domains" {
		if f.forbid {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var items []any
		for _, d := range f.domains {
			items = append(items, d)
		}
		list(items)
		return
	}
	base := "/v4/domains/7/records"
	if !strings.HasPrefix(r.URL.Path, base) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[{"reason":"Not found"}]}`)
		return
	}
	switch r.Method {
	case http.MethodGet:
		var items []any
		for _, x := range f.recs {
			items = append(items, x)
		}
		list(items)
	case http.MethodPost:
		b, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(b))
		var rec map[string]any
		_ = json.Unmarshal(b, &rec)
		if rec["type"] == "SRV" {
			svc := strings.TrimPrefix(rec["service"].(string), "_")
			proto := strings.TrimPrefix(rec["protocol"].(string), "_")
			rec["name"], rec["service"], rec["protocol"] = "_"+svc+"._"+proto, svc, proto
		}
		rec["target"] = strings.TrimSuffix(rec["target"].(string), ".")
		if rec["ttl_sec"] == nil {
			rec["ttl_sec"] = 0
		}
		f.nextID++
		rec["id"] = f.nextID
		f.recs = append(f.recs, rec)
		_ = json.NewEncoder(w).Encode(rec)
	case http.MethodDelete:
		id, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, base+"/"))
		for i, rec := range f.recs {
			if n, _ := rec["id"].(float64); int(n) == id || rec["id"] == id {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				_, _ = io.WriteString(w, "{}")
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func newFakeLinode(t *testing.T) (*fakeLinode, *linodeProvider) {
	f := &fakeLinode{domains: []lnDomain{{ID: 3, Domain: "other.org", Type: "master"}, {ID: 7, Domain: "example.com", Type: "master"}, {ID: 9, Domain: "copy.net", Type: "slave"}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &linodeProvider{APIToken: "tok", baseURL: srv.URL, pageSize: 2}
}

func lnData(t *testing.T, p *linodeProvider) []string {
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

// Parse the record the way dnshelper hands it to a provider.
func lnParsed(t *testing.T, name, typ, data string) libdns.Record {
	t.Helper()
	r, err := libdns.RR{Name: name, Type: typ, Data: data}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Issue #19: a zero priority and weight must reach the API as explicit zeros.
// The SRV record also reads back under its own name, not doubled.
func TestLinodeZeroSRVSentExplicitly(t *testing.T) {
	f, p := newFakeLinode(t)
	srv := lnParsed(t, "_autodiscover._tcp", "SRV", "0 0 443 mail.example.net.")
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(f.bodies[0]), &sent); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"priority": 0.0, "weight": 0.0, "port": 443.0, "service": "autodiscover", "protocol": "tcp"} {
		if v, ok := sent[k]; !ok || v != want {
			t.Errorf("%s: sent %v (present %v), want %v; body %s", k, v, ok, want, f.bodies[0])
		}
	}
	if f.auth != "Bearer tok" {
		t.Errorf("auth header %q", f.auth)
	}
	if got := lnData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
	del, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net"}})
	if err != nil || len(del) != 1 {
		t.Fatalf("delete by the name read back: %v %v", del, err)
	}
}

func TestLinodeRefusesWhatItCannotStore(t *testing.T) {
	f, p := newFakeLinode(t)
	ctx := context.Background()
	var ce *contract.Error
	for _, r := range []libdns.Record{
		lnParsed(t, "_sip._tcp.sub", "SRV", "10 5 5060 sip.example.net."),
		lnParsed(t, "@", "CAA", `128 issue "letsencrypt.org"`),
		lnParsed(t, "@", "HTTPS", `1 . alpn="h2"`),
	} {
		if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{r}); !errors.As(err, &ce) || ce.Code != contract.CodeUnsupported {
			t.Errorf("%s %s: want unsupported, got %v", r.RR().Name, r.RR().Type, err)
		}
	}
	if len(f.bodies) != 0 {
		t.Fatalf("refused records must not be sent: %v", f.bodies)
	}
}

func TestLinodeRecordForms(t *testing.T) {
	f, p := newFakeLinode(t)
	ctx := context.Background()
	in := []libdns.Record{
		lnParsed(t, "@", "MX", "10 mail.example.net."),
		lnParsed(t, "www", "CNAME", "target.example.net."),
		lnParsed(t, "@", "CAA", `0 issue "letsencrypt.org"`),
		lnParsed(t, "@", "TXT", `v=spf1 "quoted" back\slash -all`),
	}
	if _, err := p.AppendRecords(ctx, "example.com.", in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.bodies[0], `"name":""`) || !strings.Contains(f.bodies[0], `"priority":10`) || !strings.Contains(f.bodies[0], `"target":"mail.example.net."`) {
		t.Errorf("MX body %s", f.bodies[0])
	}
	if !strings.Contains(f.bodies[2], `"tag":"issue"`) || !strings.Contains(f.bodies[2], `"target":"letsencrypt.org"`) {
		t.Errorf("CAA body %s", f.bodies[2])
	}
	got := strings.Join(lnData(t, p), "\n")
	for _, want := range []string{"@ MX 10 mail.example.net.", "www CNAME target.example.net.", `@ CAA 0 issue "letsencrypt.org"`, `@ TXT v=spf1 "quoted" back\slash -all`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestLinodeDeleteExactAndSet(t *testing.T) {
	_, p := newFakeLinode(t)
	ctx := context.Background()
	txt := func(d string) libdns.Record { return libdns.RR{Name: "x", Type: "TXT", Data: d, TTL: 120e9} }
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("b"), txt("c"),
		libdns.RR{Name: "y", Type: "TXT", Data: "other"}}); err != nil {
		t.Fatal(err)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "TXT", Data: "nope"}}); err != nil || len(del) != 0 {
		t.Fatalf("inexact delete: %v %v", del, err)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{txt("b")}); err != nil || len(del) != 1 {
		t.Fatalf("exact delete: %v %v", del, err)
	}
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("d")}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(lnData(t, p), ","); got != "x TXT a,y TXT other,x TXT d" {
		t.Fatalf("after set: %s", got)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x"}}); err != nil || len(del) != 2 {
		t.Fatalf("name-only delete: %v %v", del, err)
	}
}

func TestLinodeZonesAndErrors(t *testing.T) {
	f, p := newFakeLinode(t)
	ctx := context.Background()
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 2 || zones[1].Name != "example.com." {
		t.Fatalf("zones (slave left out) %v %v", zones, err)
	}
	var ce *contract.Error
	if _, err := p.GetRecords(ctx, "nosuch.com."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("unknown zone: %v", err)
	}
	f.forbid = true
	if _, err := p.ListZones(ctx); !errors.As(err, &ce) || ce.Code != contract.CodeUnsupported {
		t.Fatalf("forbidden list: %v", err)
	}
}
