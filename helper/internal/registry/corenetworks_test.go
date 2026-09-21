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

// fakeCoreNetworks is an in-memory Core-Networks API: tokens from /auth/token,
// a zone list, and per-zone records that only reach "live" when committed.
type fakeCoreNetworks struct {
	mu        sync.Mutex
	records   []map[string]any
	live      []map[string]any
	logins    int
	commits   int
	deletes   []map[string]string
	badLogin  bool
	expireAll bool // answer 401 to the next authorized request
	zones     []map[string]string
}

func (f *fakeCoreNetworks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/auth/token" {
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		if f.badLogin || in["login"] != "api-user" || in["password"] != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad credentials"}`))
			return
		}
		f.logins++
		_, _ = w.Write([]byte(`{"token":"tok-` + string(rune('0'+f.logins)) + `","expires":3600}`))
		return
	}
	if f.expireAll {
		f.expireAll = false
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/dnszones/" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(f.zones)
	case !strings.HasPrefix(r.URL.Path, "/dnszones/example.com/records/"):
		w.WriteHeader(http.StatusNotFound)
	case strings.HasSuffix(r.URL.Path, "/commit"):
		f.commits++
		f.live = append([]map[string]any{}, f.records...)
	case strings.HasSuffix(r.URL.Path, "/delete"):
		var m map[string]string
		_ = json.Unmarshal(body, &m)
		f.deletes = append(f.deletes, m)
		var keep []map[string]any
		for _, rec := range f.records {
			match := true
			for k, v := range m {
				if rec[k] != v {
					match = false
				}
			}
			if !match {
				keep = append(keep, rec)
			}
		}
		f.records = keep
	case r.Method == http.MethodGet:
		out := f.records
		if out == nil {
			out = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPost:
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		if _, ok := m["ttl"]; ok {
			m["ttl"] = "300" // the API returns the TTL as a string
		} else {
			m["ttl"] = "3600"
		}
		for _, rec := range f.records {
			if rec["name"] == m["name"] && rec["type"] == m["type"] && rec["data"] == m["data"] {
				return // an existing record is not added twice, and that is not an error
			}
		}
		f.records = append(f.records, m)
	}
}

func newFakeCN(t *testing.T) (*coreNetworksProvider, *fakeCoreNetworks) {
	f := &fakeCoreNetworks{zones: []map[string]string{
		{"name": "example.com", "type": "master"}, {"name": "copy.example", "type": "slave"}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &coreNetworksProvider{Login: "api-user", Password: "secret", baseURL: srv.URL}, f
}

func cnTXT(name, data string) libdns.Record { return libdns.RR{Name: name, Type: "TXT", Data: data} }

func TestCoreNetworksLogsInOnceAndReusesTheToken(t *testing.T) {
	g, f := newFakeCN(t)
	for i := 0; i < 3; i++ {
		if _, err := g.GetRecords(context.Background(), "example.com."); err != nil {
			t.Fatal(err)
		}
	}
	if f.logins != 1 {
		t.Fatalf("want one login, got %d", f.logins)
	}
}

func TestCoreNetworksExpiredTokenIsRenewedOnce(t *testing.T) {
	g, f := newFakeCN(t)
	if _, err := g.GetRecords(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	f.expireAll = true
	if _, err := g.GetRecords(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if f.logins != 2 {
		t.Fatalf("a 401 must trigger one new login, got %d logins", f.logins)
	}
}

func TestCoreNetworksBadCredentialsNameTheStatus(t *testing.T) {
	g, _ := newFakeCN(t)
	g.Password = "wrong"
	_, err := g.GetRecords(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("the error must carry the status so it is recognised as a credential failure: %v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatal("the password must not appear in the error")
	}
}

func TestCoreNetworksChangesAreCommitted(t *testing.T) {
	g, f := newFakeCN(t)
	ctx := context.Background()
	if _, err := g.AppendRecords(ctx, "example.com", []libdns.Record{cnTXT("a", "one"), cnTXT("b", "two")}); err != nil {
		t.Fatal(err)
	}
	if f.commits != 1 || len(f.live) != 2 {
		t.Fatalf("one commit after the whole append, got %d commits and %d live records", f.commits, len(f.live))
	}
	if _, err := g.DeleteRecords(ctx, "example.com", []libdns.Record{cnTXT("a", "one")}); err != nil {
		t.Fatal(err)
	}
	if f.commits != 2 || len(f.live) != 1 {
		t.Fatalf("a delete must be committed too: %d commits, %d live", f.commits, len(f.live))
	}
	if _, err := g.GetRecords(ctx, "example.com"); err != nil || f.commits != 2 {
		t.Fatal("a read must not commit")
	}
}

func TestCoreNetworksAppendingAnExistingRecordIsNotAnError(t *testing.T) {
	g, f := newFakeCN(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := g.AppendRecords(ctx, "example.com", []libdns.Record{cnTXT("a", "one")}); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.records) != 1 {
		t.Fatalf("%v", f.records)
	}
}

func TestCoreNetworksTTLComesBackAsAString(t *testing.T) {
	g, _ := newFakeCN(t)
	ctx := context.Background()
	_, _ = g.AppendRecords(ctx, "example.com", []libdns.Record{libdns.RR{Name: "a", Type: "TXT", Data: "x", TTL: 300e9}})
	recs, err := g.GetRecords(ctx, "example.com")
	if err != nil || len(recs) != 1 || recs[0].RR().TTL.Seconds() != 300 {
		t.Fatalf("%v %v", recs, err)
	}
}

func TestCoreNetworksDeleteSendsOnlyConcreteRecords(t *testing.T) {
	g, f := newFakeCN(t)
	ctx := context.Background()
	_, _ = g.AppendRecords(ctx, "example.com", []libdns.Record{
		cnTXT("a", "one"), cnTXT("a", "two"), cnTXT("b", "three"),
		libdns.RR{Name: "www", Type: "CNAME", Data: "Host.Example.NET."}})
	// a name-only request (a wildcard for type and data) is resolved against the zone
	if _, err := g.DeleteRecords(ctx, "example.com", []libdns.Record{libdns.RR{Name: "a", Type: "TXT"}}); err != nil {
		t.Fatal(err)
	}
	for _, d := range f.deletes {
		if d["name"] == "" || d["type"] == "" || d["data"] == "" {
			t.Fatalf("a delete without name, type and data would remove more than intended: %v", d)
		}
	}
	if len(f.records) != 2 {
		t.Fatalf("only a's TXT records should be gone: %v", f.records)
	}
	// data compares like DNS: case and trailing dot do not matter for host names
	del, err := g.DeleteRecords(ctx, "example.com", []libdns.Record{libdns.RR{Name: "WWW", Type: "CNAME", Data: "host.example.net"}})
	if err != nil || len(del) != 1 {
		t.Fatalf("%v %v", del, err)
	}
	// nothing matches: nothing is sent and nothing is committed
	before, commits := len(f.deletes), f.commits
	if _, err := g.DeleteRecords(ctx, "example.com", []libdns.Record{cnTXT("zzz", "none")}); err != nil {
		t.Fatal(err)
	}
	if len(f.deletes) != before || f.commits != commits {
		t.Fatal("deleting nothing must not send a delete or a commit")
	}
	// the adapter refuses to send an incomplete delete itself
	if err := g.remove(ctx, "example.com", cnRecord{Name: "a", Type: "TXT"}); err == nil {
		t.Fatal("remove must refuse a record without data")
	}
}

func TestCoreNetworksSetReplacesTheSets(t *testing.T) {
	g, f := newFakeCN(t)
	ctx := context.Background()
	_, _ = g.AppendRecords(ctx, "example.com", []libdns.Record{cnTXT("a", "one"), cnTXT("a", "two"), cnTXT("b", "keep")})
	if _, err := g.SetRecords(ctx, "example.com", []libdns.Record{cnTXT("a", "three")}); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range f.records {
		got[r["name"].(string)+"="+r["data"].(string)] = true
	}
	if len(got) != 2 || !got["a=three"] || !got["b=keep"] {
		t.Fatalf("%v", got)
	}
}

func TestCoreNetworksListsOnlyMasterZonesAndReportsMissingZones(t *testing.T) {
	g, _ := newFakeCN(t)
	zones, err := g.ListZones(context.Background())
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com." {
		t.Fatalf("%v %v", zones, err)
	}
	_, err = g.GetRecords(context.Background(), "nothere.example")
	var ce *contract.Error
	if !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("want zone_not_found, got %v", err)
	}
}

func TestCoreNetworksCredentialCheck(t *testing.T) {
	def, ok := Get("corenetworks")
	if !ok {
		t.Fatal("not registered")
	}
	if _, err := def.Check(map[string]string{"login": "u"}); err == nil {
		t.Error("the password is required")
	}
	if _, err := def.Check(map[string]string{"login": "u", "password": "p"}); err != nil {
		t.Error(err)
	}
	if got := def.Secrets(map[string]string{"login": "u", "password": "p"}); len(got) != 1 || got[0] != "p" {
		t.Errorf("only the password is a secret: %v", got)
	}
}
