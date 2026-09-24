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

// fakeDO is an in-memory DigitalOcean domain records API for example.com.
type fakeDO struct {
	mu      sync.Mutex
	recs    []map[string]any
	nextID  int
	bodies  []string // raw POST bodies
	auth    string
	domains []string
	forbid  bool // answer 403 to the domain list
}

func (f *fakeDO) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	slice := func(n int) (int, int) {
		lo, hi := (page-1)*per, page*per
		if lo > n {
			lo = n
		}
		if hi > n {
			hi = n
		}
		return lo, hi
	}
	if r.URL.Path == "/v2/domains" {
		if f.forbid {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		lo, hi := slice(len(f.domains))
		out := []map[string]string{}
		for _, d := range f.domains[lo:hi] {
			out = append(out, map[string]string{"name": d})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"domains": out})
		return
	}
	base := "/v2/domains/example.com/records"
	if !strings.HasPrefix(r.URL.Path, base) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"id":"not_found","message":"Resource not found"}`)
		return
	}
	switch r.Method {
	case http.MethodGet:
		lo, hi := slice(len(f.recs))
		_ = json.NewEncoder(w).Encode(map[string]any{"domain_records": f.recs[lo:hi]})
	case http.MethodPost:
		b, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(b))
		var rec map[string]any
		_ = json.Unmarshal(b, &rec)
		if d, _ := rec["data"].(string); strings.Contains(d, " ") && rec["type"] == "SRV" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		if rec["ttl"] == nil {
			rec["ttl"] = 1800
		}
		// The API returns targets without the final dot.
		rec["data"] = strings.TrimSuffix(rec["data"].(string), ".")
		f.nextID++
		rec["id"] = f.nextID
		f.recs = append(f.recs, rec)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"domain_record": rec})
	case http.MethodDelete:
		id, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, base+"/"))
		for i, rec := range f.recs {
			if n, _ := rec["id"].(float64); int(n) == id || rec["id"] == id {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func newFakeDO(t *testing.T) (*fakeDO, *digitalOceanProvider) {
	f := &fakeDO{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &digitalOceanProvider{APIToken: "tok", baseURL: srv.URL, pageSize: 2}
}

func doData(t *testing.T, p *digitalOceanProvider) []string {
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

// Issue #19: a zero priority and weight must reach the API as explicit zeros in
// the structured fields, not inside data and not dropped.
func TestDigitalOceanZeroSRVSentExplicitly(t *testing.T) {
	f, p := newFakeDO(t)
	srv := libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net."}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(f.bodies[0]), &sent); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]float64{"priority": 0, "weight": 0, "port": 443} {
		if v, ok := sent[k]; !ok || v != want {
			t.Errorf("%s: sent %v (present %v), want %v; body %s", k, v, ok, want, f.bodies[0])
		}
	}
	if sent["data"] != "mail.example.net." {
		t.Errorf("data: %v", sent["data"])
	}
	if f.auth != "Bearer tok" {
		t.Errorf("auth header %q", f.auth)
	}
	if got := doData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
}

func TestDigitalOceanRecordForms(t *testing.T) {
	f, p := newFakeDO(t)
	ctx := context.Background()
	in := []libdns.Record{
		libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.net"},
		libdns.RR{Name: "www", Type: "CNAME", Data: "target.example.net"},
		libdns.RR{Name: "", Type: "TXT", Data: `v=spf1 "quoted" -all`, TTL: 5e9},
	}
	if _, err := p.AppendRecords(ctx, "example.com.", in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.bodies[0], `"data":"mail.example.net."`) || !strings.Contains(f.bodies[0], `"priority":10`) {
		t.Errorf("MX body %s", f.bodies[0])
	}
	if !strings.Contains(f.bodies[1], `"data":"target.example.net."`) {
		t.Errorf("CNAME body %s", f.bodies[1])
	}
	if !strings.Contains(f.bodies[2], `"name":"@"`) || !strings.Contains(f.bodies[2], `"ttl":30`) {
		t.Errorf("TXT body %s: want apex @ and TTL raised to 30", f.bodies[2])
	}
	got := strings.Join(doData(t, p), "\n")
	for _, want := range []string{"@ MX 10 mail.example.net.", "www CNAME target.example.net.", `@ TXT v=spf1 "quoted" -all`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "@", Type: "CAA", Data: `0 issue "letsencrypt.org"`}}); err == nil {
		t.Error("CAA must be refused")
	}
}

func TestDigitalOceanDeleteExactAndSet(t *testing.T) {
	_, p := newFakeDO(t)
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
	got := strings.Join(doData(t, p), ",")
	if got != "x TXT a,y TXT other,x TXT d" {
		t.Fatalf("after set: %s", got)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x"}}); err != nil || len(del) != 2 {
		t.Fatalf("name-only delete: %v %v", del, err)
	}
}

func TestDigitalOceanZonesAndErrors(t *testing.T) {
	f, p := newFakeDO(t)
	ctx := context.Background()
	f.domains = []string{"a.com", "b.com", "c.com"}
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 3 || zones[2].Name != "c.com." {
		t.Fatalf("zones %v %v", zones, err)
	}
	f.forbid = true
	var ce *contract.Error
	if _, err := p.ListZones(ctx); !errors.As(err, &ce) || ce.Code != contract.CodeUnsupported {
		t.Fatalf("forbidden list: %v", err)
	}
	if _, err := p.GetRecords(ctx, "other.com."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("unknown zone: %v", err)
	}
}

func TestDigitalOceanSkipsSOA(t *testing.T) {
	f, p := newFakeDO(t)
	f.recs = []map[string]any{{"id": 1, "type": "SOA", "name": "@", "data": "1800", "ttl": 1800},
		{"id": 2, "type": "NS", "name": "@", "data": "ns1.digitalocean.com", "ttl": 1800}}
	if got := doData(t, p); len(got) != 1 || got[0] != "@ NS ns1.digitalocean.com." {
		t.Fatalf("%v", got)
	}
}
