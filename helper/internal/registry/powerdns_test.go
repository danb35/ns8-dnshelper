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

// fakePowerDNS is an in-memory PowerDNS API (server "localhost") holding
// example.com. Like the real one it applies a PATCH of REPLACE and DELETE
// changes all at once, refuses a record set without a TTL or with a name that
// is not fully qualified (422, nothing applied), and answers 401 to a wrong
// key and 404 to an unknown zone.
type fakePowerDNS struct {
	mu      sync.Mutex
	sets    map[string]pdRRset // "name/TYPE"
	patches [][]byte
	key     string
	path    string
}

func (f *fakePowerDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key, f.path = r.Header.Get("X-API-Key"), r.URL.Path
	answer := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if f.key != "k" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
		return
	}
	switch p := r.URL.Path; {
	case p == "/api/v1/servers/localhost/zones":
		answer(http.StatusOK, []map[string]string{{"name": "example.com.", "kind": "Native"}, {"name": "primary.org.", "kind": "Master"},
			{"name": "copy.net.", "kind": "Slave"}, {"name": "catalog.invalid.", "kind": "Producer"}})
	case p != "/api/v1/servers/localhost/zones/example.com.":
		answer(http.StatusNotFound, map[string]string{"error": "Could not find domain"})
	case r.Method == http.MethodGet:
		var keys []string
		for k := range f.sets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []pdRRset{}
		for _, k := range keys {
			out = append(out, f.sets[k])
		}
		answer(http.StatusOK, map[string]any{"name": "example.com.", "rrsets": out})
	case r.Method == http.MethodPatch:
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		f.patches = append(f.patches, raw)
		var in struct {
			RRsets []pdRRset `json:"rrsets"`
		}
		_ = json.Unmarshal(raw, &in)
		for _, s := range in.RRsets {
			if !strings.HasSuffix(s.Name, "example.com.") {
				answer(http.StatusUnprocessableEntity, map[string]string{"error": "DNS Name '" + s.Name + "' is not canonical"})
				return
			}
			if s.ChangeType == "REPLACE" && s.TTL == 0 {
				answer(http.StatusUnprocessableEntity, map[string]string{"error": "Key 'ttl' not an Integer or not present"})
				return
			}
		}
		for _, s := range in.RRsets {
			k := s.Name + "/" + s.Type
			if s.ChangeType == "DELETE" {
				delete(f.sets, k)
			} else {
				s.ChangeType = ""
				f.sets[k] = s
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func newFakePowerDNS(t *testing.T) (*fakePowerDNS, *powerDNSProvider) {
	f := &fakePowerDNS{sets: map[string]pdRRset{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &powerDNSProvider{APIURL: srv.URL + "/api/v1/", APIKey: "k"}
}

func pdData(t *testing.T, p *powerDNSProvider) []string {
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

func TestPowerDNSBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:8081":              "http://127.0.0.1:8081/api/v1/servers/localhost",
		"https://ns1.example.com/api/v1/":    "https://ns1.example.com/api/v1/servers/localhost",
		"https://proxy.example.com/pdns/api": "https://proxy.example.com/pdns/api/v1/servers/localhost",
	} {
		if got, err := pdBaseURL(in, ""); err != nil || got != want {
			t.Errorf("%s: %s %v", in, got, err)
		}
	}
	if got, _ := pdBaseURL("http://h:8081", "other"); got != "http://h:8081/api/v1/servers/other" {
		t.Errorf("server id: %s", got)
	}
	for _, bad := range []string{"", "ns1.example.com:8081", "ftp://h/", "http://"} {
		if _, err := pdBaseURL(bad, ""); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

// Issue #19: the zero priority and weight of an SRV record must be in the
// bytes sent. PowerDNS takes the whole value as one string, so they are.
func TestPowerDNSZeroSRVSentExplicitly(t *testing.T) {
	f, p := newFakePowerDNS(t)
	srv := libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net."}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	if got := string(f.patches[0]); got != `{"rrsets":[{"name":"_autodiscover._tcp.example.com.","type":"SRV","ttl":3600,"changetype":"REPLACE","records":[{"content":"0 0 443 mail.example.net.","disabled":false}]}]}` {
		t.Errorf("body %s", got)
	}
	if f.key != "k" || f.path != "/api/v1/servers/localhost/zones/example.com." {
		t.Errorf("key %q path %q", f.key, f.path)
	}
	if got := pdData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
}

func TestPowerDNSOneRequestAndDisabledRecordsKept(t *testing.T) {
	f, p := newFakePowerDNS(t)
	ctx := context.Background()
	f.sets["x.example.com./TXT"] = pdRRset{Name: "x.example.com.", Type: "TXT", TTL: 600, Records: []pdRecord{
		{Content: `"a"`}, {Content: `"b"`}, {Content: `"off"`, Disabled: true}}}
	f.sets["example.com./A"] = pdRRset{Name: "example.com.", Type: "A", TTL: 600, Records: []pdRecord{{Content: "192.0.2.1"}}}
	if got := strings.Join(pdData(t, p), ","); got != "@ A 192.0.2.1,x TXT a,x TXT b" {
		t.Fatalf("disabled records are not returned: %s", got)
	}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{
		libdns.RR{Name: "x", Type: "TXT", Data: `say "hi"`},
		libdns.RR{Name: "Y", Type: "MX", Data: "10 mail.example.net", TTL: 120e9},
	}); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 1 {
		t.Fatalf("one PATCH expected, got %d", len(f.patches))
	}
	x := f.sets["x.example.com./TXT"]
	if x.TTL != 600 || len(x.Records) != 4 || !x.Records[3].Disabled || x.Records[2].Content != `"say \"hi\""` {
		t.Errorf("append must keep the TTL and the disabled record: %+v", x)
	}
	if y := f.sets["y.example.com./MX"]; y.TTL != 120 || y.Records[0].Content != "10 mail.example.net." {
		t.Errorf("new set: %+v", y)
	}
	// Deleting every enabled value keeps the set for its disabled record.
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "TXT"}}); err != nil || len(del) != 3 {
		t.Fatalf("delete: %v %v", del, err)
	}
	if x := f.sets["x.example.com./TXT"]; len(x.Records) != 1 || !x.Records[0].Disabled {
		t.Errorf("after delete: %+v", x)
	}
	// A set with nothing left is deleted.
	if _, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "y", Type: "MX", Data: "10 mail.example.net."}}); err != nil {
		t.Fatal(err)
	}
	if last := string(f.patches[len(f.patches)-1]); !strings.Contains(last, `"changetype":"DELETE"`) {
		t.Errorf("an emptied set must be deleted: %s", last)
	}
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "@", Type: "A", Data: "192.0.2.9"}}); err != nil {
		t.Fatal(err)
	}
	if a := f.sets["example.com./A"]; a.TTL != 600 || len(a.Records) != 1 || a.Records[0].Content != "192.0.2.9" {
		t.Errorf("set without a TTL keeps the set's TTL: %+v", a)
	}
}

func TestPowerDNSZonesAndErrors(t *testing.T) {
	_, p := newFakePowerDNS(t)
	ctx := context.Background()
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 2 || zones[0].Name != "example.com." || zones[1].Name != "primary.org." {
		t.Fatalf("native and primary zones only: %v %v", zones, err)
	}
	var ce *contract.Error
	if _, err := p.GetRecords(ctx, "other.org."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("unknown zone: %v", err)
	}
	err = p.fail("could not write records", 422, []byte(`{"error": "RRset x.example.com. IN CNAME: Conflicts with pre-existing RRset"}`))
	if err.Error() != "could not write records: PowerDNS answered 422: RRset x.example.com. IN CNAME: Conflicts with pre-existing RRset" {
		t.Fatalf("got %v", err)
	}
	p.APIKey = "wrong"
	if _, err := p.GetRecords(ctx, "example.com."); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed {
		t.Fatalf("bad key: %v", err)
	}
	p.APIURL = "ns1.example.com:8081"
	if _, err := p.ListZones(ctx); !errors.As(err, &ce) || ce.Code != contract.CodeInvalidRequest {
		t.Fatalf("bad URL: %v", err)
	}
}
