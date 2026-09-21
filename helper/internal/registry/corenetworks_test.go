package registry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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
	tooMany   bool // answer 429 to every login
	expireAll bool // answer 401 to the next authorized request
	zones     []map[string]string
}

func (f *fakeCoreNetworks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/auth/token" {
		if f.tooMany {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Zu viele Login-Versuche, versuchen Sie es später erneut."))
			return
		}
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
		w.WriteHeader(http.StatusForbidden) // what the service says to a token it does not know
		return
	}
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusForbidden)
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
		if t, ok := m["ttl"]; ok {
			if n, _ := t.(float64); n < 60 {
				w.WriteHeader(http.StatusUnsupportedMediaType) // the service's answer to a bad value
				return
			}
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

func TestCoreNetworksUnknownTokenIsRenewedOnce(t *testing.T) {
	g, f := newFakeCN(t)
	if _, err := g.GetRecords(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	f.expireAll = true
	if _, err := g.GetRecords(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if f.logins != 2 {
		t.Fatalf("a 403 must trigger one new login, got %d logins", f.logins)
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

func TestCoreNetworksTXTEncoding(t *testing.T) {
	long := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 19) // 630 bytes
	for _, tc := range []struct{ plain, sent string }{
		{"hello world", "hello world"}, // no quote or backslash: sent as it is
		{long, long},                   // and the service splits it itself
		{`a "quoted" word and a back\slash`, `"a \"quoted\" word and a back\\slash"`},
		{`"hello"`, `"\"hello\""`},
		{"", ""},
	} {
		if got := cnEncodeTXT(tc.plain); got != tc.sent {
			t.Errorf("encode %q: got %q, want %q", tc.plain, got, tc.sent)
		}
		if got := cnDecodeTXT(cnEncodeTXT(tc.plain)); got != tc.plain {
			t.Errorf("round trip of %q gave %q", tc.plain, got)
		}
	}
	// a long value with a quote is split into strings of at most 255 bytes, and is whole again after decoding
	q := strings.Repeat(`ab"cd\`, 100) // 700 bytes
	enc := cnEncodeTXT(q)
	for _, part := range strings.Split(enc, `" "`) {
		if len(strings.TrimSuffix(strings.TrimPrefix(part, `"`), `"`)) > 2*255 { // escapes add bytes
			t.Fatalf("a string is far too long: %d", len(part))
		}
	}
	if cnDecodeTXT(enc) != q {
		t.Fatal("a split value must decode to the original")
	}
	// values as other people entered them
	for in, want := range map[string]string{
		`"v=spf1 a mx ~all"`:    "v=spf1 a mx ~all",
		`"one" "two"`:           "onetwo",
		`"a \"b\" c"`:           `a "b" c`,
		`"tab\009end"`:          "tab\tend",
		`v=DKIM1; k=rsa; p=abc`: `v=DKIM1; k=rsa; p=abc`, // plain: unchanged
		`"unterminated`:         `"unterminated`,         // malformed: unchanged
		`"ok" trailing`:         `"ok" trailing`,
	} {
		if got := cnDecodeTXT(in); got != want {
			t.Errorf("decode %q: got %q, want %q", in, got, want)
		}
	}
}

func TestCoreNetworksTXTIsStoredEncodedAndReadBackPlain(t *testing.T) {
	g, f := newFakeCN(t)
	ctx := context.Background()
	plain := `a "quoted" word and a back\slash`
	if _, err := g.AppendRecords(ctx, "example.com", []libdns.Record{cnTXT("q", plain), cnTXT("p", "plain text")}); err != nil {
		t.Fatal(err)
	}
	stored := map[string]string{}
	for _, r := range f.records {
		stored[r["name"].(string)] = r["data"].(string)
	}
	if stored["q"] != `"a \"quoted\" word and a back\\slash"` || stored["p"] != "plain text" {
		t.Fatalf("stored: %v", stored)
	}
	recs, err := g.GetRecords(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range recs {
		got[r.RR().Name] = r.RR().Data
	}
	if got["q"] != plain || got["p"] != "plain text" {
		t.Fatalf("read back: %v", got)
	}
	// a record entered by someone else with quotes around an SPF value is found by its plain text
	f.records = append(f.records, map[string]any{"name": "@", "type": "TXT", "ttl": "1800", "data": `"v=spf1 a mx ~all"`})
	del, err := g.DeleteRecords(ctx, "example.com", []libdns.Record{cnTXT("@", "v=spf1 a mx ~all")})
	if err != nil || len(del) != 1 {
		t.Fatalf("%v %v", del, err)
	}
	if f.deletes[len(f.deletes)-1]["data"] != `"v=spf1 a mx ~all"` {
		t.Fatalf("the delete must carry the stored form: %v", f.deletes[len(f.deletes)-1])
	}
	if len(f.records) != 2 {
		t.Fatalf("%v", f.records)
	}
}

func TestCoreNetworksShortTTLIsRaisedToTheMinimum(t *testing.T) {
	g, _ := newFakeCN(t)
	ctx := context.Background()
	for _, ttl := range []int{1, 30, 59, 60} {
		if _, err := g.AppendRecords(ctx, "example.com", []libdns.Record{libdns.RR{Name: "t", Type: "TXT", Data: "v" + string(rune('a'+ttl%26)), TTL: time.Duration(ttl) * time.Second}}); err != nil {
			t.Fatalf("ttl %d: %v", ttl, err)
		}
	}
}

func TestCoreNetworksTokenIsKeptBetweenRuns(t *testing.T) {
	g, f := newFakeCN(t)
	dir := t.TempDir() + "/cache"
	run := func(pw string) error { // a fresh provider each time, like a fresh run of the helper
		p := &coreNetworksProvider{Login: "api-user", Password: pw, baseURL: g.baseURL, cacheDir: dir}
		_, err := p.GetRecords(context.Background(), "example.com")
		return err
	}
	for i := 0; i < 3; i++ {
		if err := run("secret"); err != nil {
			t.Fatal(err)
		}
	}
	if f.logins != 1 {
		t.Fatalf("three runs must share one login, got %d", f.logins)
	}
	// the token is private
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("the cache directory must be 0700: %v %v", st, err)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatalf("one token file, got %d", len(files))
	}
	if st, _ := os.Stat(dir + "/" + files[0].Name()); st.Mode().Perm() != 0o600 {
		t.Fatalf("the token file must be 0600, got %v", st.Mode().Perm())
	}
	// another password never finds this token: it logs in, and is refused
	if err := run("other"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a different password must not reuse the token: %v", err)
	}
	// a token the service stopped accepting is dropped and replaced
	f.expireAll = true
	if err := run("secret"); err != nil {
		t.Fatal(err)
	}
	if f.logins != 2 {
		t.Fatalf("the refused token must be replaced by one new login, got %d", f.logins)
	}
	if err := run("secret"); err != nil || f.logins != 2 {
		t.Fatalf("and the new one is reused: %v, %d logins", err, f.logins)
	}
}

func TestCoreNetworksWithoutACacheDirNothingIsWritten(t *testing.T) {
	g, f := newFakeCN(t)
	for i := 0; i < 2; i++ {
		p := &coreNetworksProvider{Login: "api-user", Password: "secret", baseURL: g.baseURL}
		if _, err := p.GetRecords(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if f.logins != 2 {
		t.Fatalf("without a cache every run logs in, got %d", f.logins)
	}
}

func TestCoreNetworksRateLimitedLoginSaysSo(t *testing.T) {
	g, f := newFakeCN(t)
	f.tooMany = true
	_, err := g.GetRecords(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "limits the number of logins") {
		t.Fatalf("%v", err)
	}
}
