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

// fakePorkbun is an in-memory Porkbun API holding example.com. Like the real
// one it returns names fully qualified, prio as a string or null, and answers
// errors with HTTP 400 and a code.
type fakePorkbun struct {
	mu     sync.Mutex
	recs   []map[string]any
	nextID int
	bodies []map[string]any // decoded create bodies
	keys   string
}

func (f *fakePorkbun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.keys = body["apikey"].(string) + "/" + body["secretapikey"].(string)
	fail := func(code, msg string) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ERROR", "code": code, "message": msg})
	}
	if body["apikey"] != "pk1" {
		fail("INVALID_API_KEYS_001", "Invalid API key. (001)")
		return
	}
	ok := func(extra map[string]any) {
		extra["status"] = "SUCCESS"
		_ = json.NewEncoder(w).Encode(extra)
	}
	switch p := r.URL.Path; {
	case p == "/domain/listAll":
		ok(map[string]any{"domains": []map[string]string{{"domain": "example.com"}}})
	case !strings.HasSuffix(strings.SplitN(strings.TrimPrefix(p, "/dns/"), "/", 3)[1], "example.com"):
		fail("INVALID_DOMAIN", "Invalid domain.")
	case strings.HasPrefix(p, "/dns/retrieve/"):
		ok(map[string]any{"records": f.recs})
	case strings.HasPrefix(p, "/dns/create/"):
		f.bodies = append(f.bodies, body)
		f.nextID++
		name := "example.com"
		if n, _ := body["name"].(string); n != "" {
			name = n + ".example.com"
		}
		rec := map[string]any{"id": strconv.Itoa(f.nextID), "name": name, "type": body["type"], "content": body["content"], "ttl": "600", "prio": nil}
		if t, ok := body["ttl"].(string); ok {
			rec["ttl"] = t
		}
		if p, ok := body["prio"]; ok {
			rec["prio"] = p
		}
		f.recs = append(f.recs, rec)
		ok(map[string]any{"id": f.nextID})
	case strings.HasPrefix(p, "/dns/delete/"):
		id := p[strings.LastIndex(p, "/")+1:]
		for i, rec := range f.recs {
			if rec["id"] == id {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				ok(map[string]any{})
				return
			}
		}
		fail("NOT_FOUND", "Record not found")
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "{}")
	}
}

func newFakePorkbun(t *testing.T) (*fakePorkbun, *porkbunProvider) {
	f := &fakePorkbun{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &porkbunProvider{APIKey: "pk1", SecretKey: "sk1", baseURL: srv.URL}
}

func pbData(t *testing.T, p *porkbunProvider) []string {
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

// Issue #19: a zero priority must reach the API explicitly, and a zero weight
// must stay in the content.
func TestPorkbunZeroSRVSentExplicitly(t *testing.T) {
	f, p := newFakePorkbun(t)
	srv := libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net."}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	b := f.bodies[0]
	if v, ok := b["prio"]; !ok || v != "0" {
		t.Errorf("prio: sent %v (present %v), want \"0\"; body %v", v, ok, b)
	}
	if b["content"] != "0 443 mail.example.net." || b["name"] != "_autodiscover._tcp" {
		t.Errorf("body %v", b)
	}
	if f.keys != "pk1/sk1" {
		t.Errorf("keys %q", f.keys)
	}
	if got := pbData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
}

func TestPorkbunRecordForms(t *testing.T) {
	f, p := newFakePorkbun(t)
	ctx := context.Background()
	in := []libdns.Record{
		libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.net"},
		libdns.RR{Name: "www", Type: "CNAME", Data: "target.example.net"},
		libdns.RR{Name: "@", Type: "TXT", Data: `v=spf1 "quoted" -all`, TTL: 60e9},
	}
	if _, err := p.AppendRecords(ctx, "example.com.", in); err != nil {
		t.Fatal(err)
	}
	if b := f.bodies[0]; b["name"] != "" || b["prio"] != "10" || b["content"] != "mail.example.net" {
		t.Errorf("MX body %v", b)
	}
	if b := f.bodies[2]; b["ttl"] != "60" {
		t.Errorf("TXT body %v", b)
	}
	if _, ok := f.bodies[1]["prio"]; ok {
		t.Errorf("CNAME must not carry a prio: %v", f.bodies[1])
	}
	got := strings.Join(pbData(t, p), "\n")
	for _, want := range []string{"@ MX 10 mail.example.net.", "www CNAME target.example.net.", `@ TXT v=spf1 "quoted" -all`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestPorkbunDeleteExactAndSet(t *testing.T) {
	_, p := newFakePorkbun(t)
	ctx := context.Background()
	txt := func(d string) libdns.Record { return libdns.RR{Name: "x", Type: "TXT", Data: d, TTL: 600e9} }
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
	if got := strings.Join(pbData(t, p), ","); got != "x TXT a,y TXT other,x TXT d" {
		t.Fatalf("after set: %s", got)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x"}}); err != nil || len(del) != 2 {
		t.Fatalf("name-only delete: %v %v", del, err)
	}
}

func TestPorkbunZonesAndErrors(t *testing.T) {
	_, p := newFakePorkbun(t)
	ctx := context.Background()
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com." {
		t.Fatalf("zones %v %v", zones, err)
	}
	var ce *contract.Error
	if _, err := p.GetRecords(ctx, "other.org."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("unknown zone: %v", err)
	}
	p.APIKey = "wrong"
	if _, err := p.GetRecords(ctx, "example.com."); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed {
		t.Fatalf("bad key: %v", err)
	}
}

func TestPorkbunReadsNumericPrio(t *testing.T) {
	var r pbRecord
	if err := json.Unmarshal([]byte(`{"id":"1","name":"example.com","type":"MX","content":"mail.example.net","ttl":600,"prio":5}`), &r); err != nil {
		t.Fatal(err)
	}
	if got := r.toLibdns("example.com.").RR(); got.Name != "@" || got.Data != "5 mail.example.net." || got.TTL != 600e9 {
		t.Fatalf("%+v", got)
	}
}
