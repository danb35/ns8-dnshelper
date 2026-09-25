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

// fakeIONOS is an in-memory IONOS DNS API holding example.com (zone id "z1").
// Like the real one it requires a prio for MX and SRV, stores names in lower
// case and targets without the final dot, writes IPv6 addresses in full, and
// answers 401 to a wrong key and to a zone id the account does not have.
type fakeIONOS struct {
	mu     sync.Mutex
	recs   []ioRecord
	nextID int
	posts  [][]byte
	key    string
}

func (f *fakeIONOS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = r.Header.Get("X-API-Key")
	answer := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if f.key != "pre.sec" {
		answer(http.StatusUnauthorized, map[string]string{"message": "Missing or invalid API key."})
		return
	}
	switch p := r.URL.Path; {
	case p == "/zones":
		answer(http.StatusOK, []map[string]string{{"name": "example.com", "id": "z1", "type": "NATIVE"}, {"name": "copy.org", "id": "z2", "type": "SLAVE"}})
	case !strings.HasPrefix(p, "/zones/z1"):
		answer(http.StatusUnauthorized, []map[string]string{{"code": "UNAUTHORIZED", "message": "The customer is not authorized to do this operation."}})
	case p == "/zones/z1" && r.Method == http.MethodGet:
		answer(http.StatusOK, map[string]any{"name": "example.com", "id": "z1", "records": f.recs})
	case p == "/zones/z1/records" && r.Method == http.MethodPost:
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		f.posts = append(f.posts, raw)
		var in []ioRecord
		_ = json.Unmarshal(raw, &in)
		for _, rec := range in {
			if (rec.Type == "MX" || rec.Type == "SRV") && rec.Prio == nil {
				answer(http.StatusBadRequest, []map[string]any{{"code": "INVALID_RECORD", "message": "Record is invalid.", "parameters": map[string]any{"requiredFields": []string{"prio"}}}})
				return
			}
			if rec.TTL != 0 && rec.TTL < 60 {
				answer(http.StatusBadRequest, []map[string]any{{"code": "INVALID_RECORD", "message": "Record is invalid.", "parameters": map[string]any{"invalidFields": []string{"ttl"}}}})
				return
			}
		}
		var made []ioRecord
		for _, rec := range in {
			f.nextID++
			rec.ID = "r" + strconv.Itoa(f.nextID)
			rec.Name = strings.ToLower(rec.Name)
			if rec.TTL == 0 {
				rec.TTL = 3600
			}
			switch rec.Type {
			case "MX", "SRV", "CNAME":
				rec.Content = strings.TrimSuffix(rec.Content, ".")
			case "AAAA":
				rec.Content = "2001:db8:0:0:0:0:0:1"
			}
			f.recs = append(f.recs, rec)
			made = append(made, rec)
		}
		answer(http.StatusCreated, made)
	case strings.HasPrefix(p, "/zones/z1/records/") && r.Method == http.MethodDelete:
		id := p[strings.LastIndex(p, "/")+1:]
		for i, rec := range f.recs {
			if rec.ID == id {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		answer(http.StatusNotFound, []map[string]string{{"code": "RECORD_NOT_FOUND", "message": "Record not found."}})
	}
}

func newFakeIONOS(t *testing.T) (*fakeIONOS, *ionosProvider) {
	f := &fakeIONOS{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &ionosProvider{Prefix: "pre", Secret: "sec", baseURL: srv.URL}
}

func ioData(t *testing.T, p *ionosProvider) []string {
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

// Issue #19: a zero priority must reach the API explicitly (IONOS refuses an
// MX or SRV without one), and a zero weight must stay in the content.
func TestIONOSZeroSRVSentExplicitly(t *testing.T) {
	f, p := newFakeIONOS(t)
	srv := libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net."}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	if got := string(f.posts[0]); got != `[{"name":"_autodiscover._tcp.example.com","type":"SRV","content":"0 443 mail.example.net.","prio":0}]` {
		t.Errorf("body %s", got)
	}
	if f.key != "pre.sec" {
		t.Errorf("key %q", f.key)
	}
	if got := ioData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
}

func TestIONOSRecordForms(t *testing.T) {
	f, p := newFakeIONOS(t)
	ctx := context.Background()
	in := []libdns.Record{
		libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.net", TTL: 30e9},
		libdns.RR{Name: "WWW", Type: "CNAME", Data: "target.example.net"},
		libdns.RR{Name: "@", Type: "TXT", Data: `say "hi" \ café`},
		libdns.RR{Name: "v6", Type: "AAAA", Data: "2001:db8::1"},
	}
	if _, err := p.AppendRecords(ctx, "example.com.", in); err != nil {
		t.Fatal(err)
	}
	if len(f.posts) != 1 {
		t.Fatalf("one request for all records, got %d", len(f.posts))
	}
	var sent []map[string]any
	_ = json.Unmarshal(f.posts[0], &sent)
	if s := sent[0]; s["name"] != "example.com" || s["prio"] != float64(10) || s["content"] != "mail.example.net." || s["ttl"] != float64(60) {
		t.Errorf("MX %v (TTL raised to 60)", s)
	}
	if s := sent[1]; s["name"] != "www.example.com" {
		t.Errorf("names are sent fully qualified, in lower case: %v", s)
	}
	if s := sent[2]; s["content"] != `"say \"hi\" \\ caf\195\169"` {
		t.Errorf("TXT must be sent quoted and escaped: %v", s["content"])
	}
	if _, ok := sent[3]["prio"]; ok {
		t.Errorf("an AAAA record must not carry a prio: %v", sent[3])
	}
	got := strings.Join(ioData(t, p), "\n")
	for _, want := range []string{"@ MX 10 mail.example.net.", "www CNAME target.example.net.", `@ TXT say "hi" \ café`, "v6 AAAA 2001:db8::1"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestIONOSDeleteSetAndDisabledRecords(t *testing.T) {
	f, p := newFakeIONOS(t)
	ctx := context.Background()
	f.recs = []ioRecord{{ID: "off", Name: "x.example.com", Type: "TXT", Content: `"off"`, TTL: 300, Disabled: true}}
	txt := func(d string) libdns.Record { return libdns.RR{Name: "x", Type: "TXT", Data: d, TTL: 300e9} }
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("b"), txt("c")}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ioData(t, p), ","); got != "x TXT a,x TXT b,x TXT c" {
		t.Fatalf("disabled records are not returned: %s", got)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{txt("b")}); err != nil || len(del) != 1 {
		t.Fatalf("exact delete: %v %v", del, err)
	}
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{txt("a"), txt("d")}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ioData(t, p), ","); got != "x TXT a,x TXT d" {
		t.Fatalf("after set: %s", got)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x"}}); err != nil || len(del) != 2 {
		t.Fatalf("name-only delete: %v %v", del, err)
	}
	if len(f.recs) != 1 || f.recs[0].ID != "off" {
		t.Fatalf("the disabled record must be left alone: %+v", f.recs)
	}
}

func TestIONOSZonesAndErrors(t *testing.T) {
	_, p := newFakeIONOS(t)
	ctx := context.Background()
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com." {
		t.Fatalf("native zones only: %v %v", zones, err)
	}
	var ce *contract.Error
	if _, err := p.GetRecords(ctx, "copy.org."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("zone not in the list: %v", err)
	}
	err = p.fail("could not create records", 400, []byte(`[{"code":"INVALID_RECORD","message":"Record is invalid.","parameters":{"invalidFields":["content"]}}]`))
	if err.Error() != "could not create records: IONOS answered 400: Record is invalid. (content)" {
		t.Fatalf("got %v", err)
	}
	p.Secret = "wrong"
	p.zoneIDs = nil
	if _, err := p.GetRecords(ctx, "example.com."); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed {
		t.Fatalf("bad key: %v", err)
	}
}
