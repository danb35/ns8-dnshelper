package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// fakeVultr is an in-memory Vultr API holding example.com. Like the real one
// it requires a priority for MX and SRV (-1 is read back for other types),
// stores TXT values quoted and MX/CNAME targets without the final dot, pages
// lists with a cursor, and answers 401 to a wrong token and 404 to an unknown
// domain.
type fakeVultr struct {
	mu     sync.Mutex
	recs   []vuRecord
	nextID int
	bodies []map[string]any // decoded create bodies
	auth   string
}

func (f *fakeVultr) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	answer := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if f.auth != "Bearer tok" {
		answer(http.StatusUnauthorized, map[string]any{"error": "Invalid API token.", "status": 401})
		return
	}
	page := func(n int) (int, int, string) {
		size, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		start, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
		end, next := start+size, ""
		if end < n {
			next = strconv.Itoa(end)
		} else {
			end = n
		}
		return start, end, next
	}
	p := r.URL.Path
	switch {
	case p == "/domains":
		answer(http.StatusOK, map[string]any{"domains": []map[string]string{{"domain": "example.com"}}, "meta": map[string]any{"links": map[string]string{"next": ""}}})
	case !strings.HasPrefix(p, "/domains/example.com/records"):
		answer(http.StatusNotFound, map[string]any{"error": "Invalid domain.", "status": 404})
	case r.Method == http.MethodGet:
		start, end, next := page(len(f.recs))
		answer(http.StatusOK, map[string]any{"records": f.recs[start:end], "meta": map[string]any{"links": map[string]string{"next": next}}})
	case r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.bodies = append(f.bodies, body)
		rec := vuRecord{Type: body["type"].(string), Name: strings.ToLower(body["name"].(string)), Data: body["data"].(string), TTL: 300}
		if t, ok := body["ttl"].(float64); ok {
			rec.TTL = int(t)
		}
		prio := -1
		if rec.Type == "MX" || rec.Type == "SRV" {
			p, ok := body["priority"].(float64)
			if !ok {
				answer(http.StatusBadRequest, map[string]any{"error": "Priority should be set when type is MX or SRV.", "status": 400})
				return
			}
			prio = int(p)
		}
		rec.Priority = &prio
		switch rec.Type {
		case "TXT":
			rec.Data = `"` + rec.Data + `"`
		case "MX", "CNAME":
			rec.Data = strings.TrimSuffix(rec.Data, ".")
		}
		f.nextID++
		rec.ID = "id-" + strconv.Itoa(f.nextID)
		f.recs = append(f.recs, rec)
		answer(http.StatusCreated, map[string]any{"record": rec})
	case r.Method == http.MethodDelete:
		id := p[strings.LastIndex(p, "/")+1:]
		for i, rec := range f.recs {
			if rec.ID == id {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		answer(http.StatusNotFound, map[string]any{"error": "Invalid record.", "status": 404})
	}
}

func newFakeVultr(t *testing.T) (*fakeVultr, *vultrProvider) {
	f := &fakeVultr{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &vultrProvider{APIToken: "tok", baseURL: srv.URL, perPage: 2}
}

func vuData(t *testing.T, p *vultrProvider) []string {
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

// Issue #19: a zero priority must reach the API explicitly (Vultr refuses an
// MX or SRV without one), and a zero weight must stay in the data.
func TestVultrZeroSRVSentExplicitly(t *testing.T) {
	f, p := newFakeVultr(t)
	srv := libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net."}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	b := f.bodies[0]
	if v, ok := b["priority"]; !ok || v != float64(0) {
		t.Errorf("priority: sent %v (present %v), want 0; body %v", v, ok, b)
	}
	if b["data"] != "0 443 mail.example.net." || b["name"] != "_autodiscover._tcp" {
		t.Errorf("body %v", b)
	}
	if f.auth != "Bearer tok" {
		t.Errorf("auth %q", f.auth)
	}
	if got := vuData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
}

func TestVultrRecordForms(t *testing.T) {
	f, p := newFakeVultr(t)
	ctx := context.Background()
	in := []libdns.Record{
		libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.net"},
		libdns.RR{Name: "WWW", Type: "CNAME", Data: "target.example.net"},
		libdns.RR{Name: "@", Type: "TXT", Data: "v=spf1 mx -all", TTL: 30e9},
		libdns.RR{Name: "@", Type: "A", Data: "192.0.2.1"},
	}
	if _, err := p.AppendRecords(ctx, "example.com.", in); err != nil {
		t.Fatal(err)
	}
	if b := f.bodies[0]; b["name"] != "" || b["priority"] != float64(10) || b["data"] != "mail.example.net." {
		t.Errorf("MX body %v", b)
	}
	if b := f.bodies[1]; b["name"] != "www" {
		t.Errorf("names are sent in lower case: %v", b)
	}
	if b := f.bodies[2]; b["ttl"] != float64(60) || b["data"] != "v=spf1 mx -all" {
		t.Errorf("TXT body %v (TTL raised to 60, value unquoted)", b)
	}
	if _, ok := f.bodies[3]["priority"]; ok {
		t.Errorf("an A record must not carry a priority: %v", f.bodies[3])
	}
	got := strings.Join(vuData(t, p), "\n")
	for _, want := range []string{"@ MX 10 mail.example.net.", "www CNAME target.example.net.", "@ TXT v=spf1 mx -all", "@ A 192.0.2.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestVultrDeleteExactAndSet(t *testing.T) {
	_, p := newFakeVultr(t)
	ctx := context.Background()
	txt := func(d string) libdns.Record { return libdns.RR{Name: "x", Type: "TXT", Data: d, TTL: 300e9} }
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("b"), txt("c"),
		libdns.RR{Name: "x", Type: "A", Data: "192.0.2.1"}}); err != nil {
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
	if got := strings.Join(vuData(t, p), ","); got != "x TXT a,x A 192.0.2.1,x TXT d" {
		t.Fatalf("after set (the A record with the same name stays): %s", got)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "TXT"}}); err != nil || len(del) != 2 {
		t.Fatalf("type-only delete: %v %v", del, err)
	}
	if got := strings.Join(vuData(t, p), ","); got != "x A 192.0.2.1" {
		t.Fatalf("after delete: %s", got)
	}
}

func TestVultrZonesAndErrors(t *testing.T) {
	_, p := newFakeVultr(t)
	ctx := context.Background()
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com." {
		t.Fatalf("zones %v %v", zones, err)
	}
	var ce *contract.Error
	if _, err := p.GetRecords(ctx, "other.org."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("unknown zone: %v", err)
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "SRV", Data: "0 443 t."}}); err == nil {
		t.Error("a malformed SRV value must be refused")
	}
	p.APIToken = "wrong"
	if _, err := p.GetRecords(ctx, "example.com."); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed {
		t.Fatalf("bad token: %v", err)
	}
}

// The priority Vultr reads back for types without one (-1) must not leak into
// the value.
func TestVultrReadsPriorityOnlyForMXAndSRV(t *testing.T) {
	var r vuRecord
	if err := json.Unmarshal([]byte(`{"id":"1","type":"MX","name":"","data":"mail.example.net","priority":-1,"ttl":300}`), &r); err != nil {
		t.Fatal(err)
	}
	if got := r.toLibdns(); got.Name != "@" || got.Data != "0 mail.example.net." || got.TTL != 300e9 {
		t.Fatalf("%+v", got)
	}
	_ = json.Unmarshal([]byte(`{"id":"2","type":"TXT","name":"x","data":"\"a\" \"b\"","priority":-1,"ttl":300}`), &r)
	if got := r.toLibdns(); got.Data != "ab" {
		t.Fatalf("%+v", got)
	}
}
