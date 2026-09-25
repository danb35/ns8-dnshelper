package registry

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

// fakeGoogle is a token endpoint and an in-memory Cloud DNS API for project
// "proj", holding the public zone example.com (managed zone "ex") and a
// private zone. The token endpoint checks the JWT's signature against the
// service account's public key. A change must delete sets exactly as they
// are, and is reported "pending" once before it is "done".
type fakeGoogle struct {
	mu      sync.Mutex
	pub     *rsa.PublicKey
	sets    map[string]gdnsRRset // "name/TYPE"
	changes [][]byte
	polls   int
	claims  map[string]any
	auth    string
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	answer := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		parts := strings.Split(r.PostForm.Get("assertion"), ".")
		sig, _ := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if len(parts) != 3 || rsa.VerifyPKCS1v15(f.pub, crypto.SHA256, sum[:], sig) != nil {
			answer(http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
			return
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(raw, &f.claims)
		answer(http.StatusOK, map[string]any{"access_token": "at-1", "expires_in": 3600, "token_type": "Bearer"})
		return
	}
	f.auth = r.Header.Get("Authorization")
	p := strings.TrimPrefix(r.URL.Path, "/dns/v1/projects/proj")
	switch {
	case p == r.URL.Path:
		answer(http.StatusForbidden, map[string]any{"error": map[string]any{"code": 403, "message": "Forbidden"}})
	case p == "/managedZones":
		answer(http.StatusOK, map[string]any{"managedZones": []map[string]string{
			{"name": "ex", "dnsName": "example.com.", "visibility": "public"},
			{"name": "inside", "dnsName": "corp.example.", "visibility": "private"}}})
	case p == "/managedZones/ex/rrsets":
		var keys []string
		for k := range f.sets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []gdnsRRset{}
		for _, k := range keys {
			out = append(out, f.sets[k])
		}
		answer(http.StatusOK, map[string]any{"rrsets": out})
	case p == "/managedZones/ex/changes" && r.Method == http.MethodPost:
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		f.changes = append(f.changes, raw)
		var ch struct{ Additions, Deletions []gdnsRRset }
		_ = json.Unmarshal(raw, &ch)
		for _, d := range ch.Deletions {
			have, ok := f.sets[d.Name+"/"+d.Type]
			hb, _ := json.Marshal(have)
			db, _ := json.Marshal(d)
			if !ok || string(hb) != string(db) {
				answer(http.StatusPreconditionFailed, map[string]any{"error": map[string]any{"code": 412, "message": "The resource does not match"}})
				return
			}
		}
		for _, d := range ch.Deletions {
			delete(f.sets, d.Name+"/"+d.Type)
		}
		for _, a := range ch.Additions {
			f.sets[a.Name+"/"+a.Type] = a
		}
		answer(http.StatusOK, map[string]string{"id": "7", "status": "pending"})
	case p == "/managedZones/ex/changes/7":
		f.polls++
		answer(http.StatusOK, map[string]string{"id": "7", "status": "done"})
	default:
		answer(http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404, "message": "The 'parameters.managedZone' resource named 'x' does not exist."}})
	}
}

func testKey(t *testing.T, tokenURI string) (string, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	key, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "proj", "private_key_id": "kid1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "dnshelper@proj.iam.gserviceaccount.com", "token_uri": tokenURI,
	})
	return string(key), &priv.PublicKey
}

func newFakeGoogle(t *testing.T) (*fakeGoogle, *googleDNSProvider) {
	f := &fakeGoogle{sets: map[string]gdnsRRset{}}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	key, pub := testKey(t, srv.URL+"/token")
	f.pub = pub
	return f, &googleDNSProvider{KeyJSON: key, baseURL: srv.URL + "/dns/v1", client: srv.Client()}
}

func gdData(t *testing.T, p *googleDNSProvider) []string {
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

func TestGoogleKeyChecks(t *testing.T) {
	good, _ := testKey(t, "https://oauth2.googleapis.com/token")
	if _, _, err := parseGCPKey(good); err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	_ = json.Unmarshal([]byte(good), &m)
	bad := func(field, value string) string {
		c := map[string]string{}
		for k, v := range m {
			c[k] = v
		}
		c[field] = value
		b, _ := json.Marshal(c)
		return string(b)
	}
	for name, key := range map[string]string{
		"not JSON":     "-----BEGIN PRIVATE KEY-----",
		"user account": bad("type", "authorized_user"),
		"no PEM":       bad("private_key", "MIIE"),
		"http token":   bad("token_uri", "http://oauth2.googleapis.com/token"),
	} {
		_, _, err := parseGCPKey(key)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "MIIE") {
			t.Errorf("%s: message shows the key: %v", name, err)
		}
	}
	d, _ := Get("googleclouddns")
	if _, err := d.Check(map[string]string{"service_account_key": "{}"}); err == nil || !strings.Contains(err.Error(), "service_account_key") {
		t.Errorf("Check: %v", err)
	}
}

// Issue #19: the zero priority and weight of an SRV record must be in the
// bytes sent. Cloud DNS takes the whole value as one string, so they are.
func TestGoogleZeroSRVAndSignedToken(t *testing.T) {
	f, p := newFakeGoogle(t)
	srv := libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", Data: "0 0 443 mail.example.net."}
	if _, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{srv}); err != nil {
		t.Fatal(err)
	}
	if got := string(f.changes[0]); got != `{"additions":[{"name":"_autodiscover._tcp.example.com.","type":"SRV","ttl":300,"rrdatas":["0 0 443 mail.example.net."]}]}` {
		t.Errorf("change %s", got)
	}
	if f.auth != "Bearer at-1" || f.claims["iss"] != "dnshelper@proj.iam.gserviceaccount.com" || f.claims["scope"] != googleDNSScope {
		t.Errorf("auth %q claims %v", f.auth, f.claims)
	}
	if f.polls != 1 {
		t.Errorf("a pending change must be followed until done (%d polls)", f.polls)
	}
	if got := gdData(t, p); len(got) != 1 || got[0] != "_autodiscover._tcp SRV 0 0 443 mail.example.net." {
		t.Fatalf("read back %v", got)
	}
}

func TestGoogleChangesDeleteTheSetAsItIs(t *testing.T) {
	f, p := newFakeGoogle(t)
	ctx := context.Background()
	f.sets["x.example.com./TXT"] = gdnsRRset{Name: "x.example.com.", Type: "TXT", TTL: 600, Rrdatas: []string{`"a"`, `"b"`}}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "X", Type: "TXT", Data: "café"}}); err != nil {
		t.Fatal(err)
	}
	if got := string(f.changes[0]); got != `{"additions":[{"name":"x.example.com.","type":"TXT","ttl":600,"rrdatas":["\"a\"","\"b\"","\"caf\\195\\169\""]}],"deletions":[{"name":"x.example.com.","type":"TXT","ttl":600,"rrdatas":["\"a\"","\"b\""]}]}` {
		t.Errorf("change %s", got)
	}
	if got := strings.Join(gdData(t, p), ","); got != "x TXT a,x TXT b,x TXT café" {
		t.Errorf("read back %s", got)
	}
	if del, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "x", Type: "TXT"}}); err != nil || len(del) != 3 {
		t.Fatalf("delete: %v %v", del, err)
	}
	if last := string(f.changes[len(f.changes)-1]); strings.Contains(last, "additions") {
		t.Errorf("an emptied set is only deleted: %s", last)
	}
	f.sets["geo.example.com./A"] = gdnsRRset{Name: "geo.example.com.", Type: "A", TTL: 300, RoutingPolicy: json.RawMessage(`{"geo":{}}`)}
	var ce *contract.Error
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{libdns.RR{Name: "geo", Type: "A", Data: "192.0.2.1"}}); !errors.As(err, &ce) || ce.Code != contract.CodeUnsupported {
		t.Errorf("routing policy: %v", err)
	}
}

func TestGoogleZonesAndErrors(t *testing.T) {
	_, p := newFakeGoogle(t)
	ctx := context.Background()
	zones, err := p.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com." {
		t.Fatalf("public zones only: %v %v", zones, err)
	}
	var ce *contract.Error
	if _, err := p.GetRecords(ctx, "corp.example."); !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("private zone: %v", err)
	}
	p2 := &googleDNSProvider{KeyJSON: p.KeyJSON, Project: "other", baseURL: p.baseURL, client: p.client}
	if _, err := p2.ListZones(ctx); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed {
		t.Fatalf("other project: %v", err)
	}
	unknown, _ := testKey(t, "")
	var m map[string]string
	_ = json.Unmarshal([]byte(unknown), &m)
	var pm map[string]string
	_ = json.Unmarshal([]byte(p.KeyJSON), &pm)
	m["token_uri"] = pm["token_uri"]
	b, _ := json.Marshal(m)
	p3 := &googleDNSProvider{KeyJSON: string(b), baseURL: p.baseURL, client: p.client}
	if _, err := p3.ListZones(ctx); !errors.As(err, &ce) || ce.Code != contract.CodeAuthFailed || !strings.Contains(ce.Message, "invalid_grant") {
		t.Fatalf("unknown key: %v", err)
	}
}
