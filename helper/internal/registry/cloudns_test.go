package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/cloudns"
	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

func TestClouDNSNeedsExactlyOneLogin(t *testing.T) {
	d, _ := Get("cloudns")
	for _, c := range []map[string]string{
		{"auth_password": "pw"},
		{"auth_password": "pw", "auth_id": "1", "sub_auth_id": "2"},
		{"auth_password": "pw", "sub_auth_id": "2", "sub_auth_user": "u"},
	} {
		if _, err := d.Check(c); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
	for _, f := range []string{"auth_id", "sub_auth_id", "sub_auth_user"} {
		if _, err := d.Check(map[string]string{"auth_password": "pw", f: "x"}); err != nil {
			t.Errorf("%s alone refused: %v", f, err)
		}
	}
	if s := d.Secrets(map[string]string{"auth_password": "pw", "sub_auth_id": "2"}); len(s) != 1 || s[0] != "pw" {
		t.Errorf("secrets: %v", s)
	}
}

func TestClouDNSErrorMapping(t *testing.T) {
	var ce *contract.Error
	auth := errors.New(`cloudns: listing zones: API request failed: Invalid authentication, incorrect auth-id or auth-password.`)
	if !errors.As(clouDNSError(auth), &ce) || ce.Code != contract.CodeAuthFailed {
		t.Errorf("auth: %v", clouDNSError(auth))
	}
	other := errors.New("cloudns: adding record \"x\": API request failed: This is not a valid IP address.")
	if clouDNSError(other) != other {
		t.Error("other errors must pass through")
	}
	if clouDNSError(nil) != nil {
		t.Error("nil")
	}
}

// fakeClouDNS records the forms the package sends.
type fakeClouDNS struct {
	mu    sync.Mutex
	forms []url.Values
}

func (f *fakeClouDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.forms = append(f.forms, r.PostForm)
	f.mu.Unlock()
	if r.URL.RawQuery != "" {
		http.Error(w, "credentials in the URL", http.StatusBadRequest)
		return
	}
	_, _ = w.Write([]byte(`{"status":"Success","statusDescription":"The record was added successfully."}`))
}

// Issue #19: a zero SRV priority and weight, and a zero MX preference, must be
// sent as an explicit 0, not left out.
func TestClouDNSSendsZeroPriorityWeightAndPort(t *testing.T) {
	f := &fakeClouDNS{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	p := clouDNSProvider{&cloudns.Provider{SubAuthId: "1", AuthPassword: "pw", BaseURL: srv.URL + "/dns/", OperationRetries: 1}}
	recs := []libdns.Record{
		libdns.RR{Name: "_autodiscover._tcp", Type: "SRV", TTL: 300 * time.Second, Data: "0 0 443 mail.example.com."},
		libdns.RR{Name: "@", Type: "MX", TTL: 300 * time.Second, Data: "0 mx.example.com."},
	}
	if _, err := p.AppendRecords(context.Background(), "example.com.", recs); err != nil {
		t.Fatal(err)
	}
	if len(f.forms) != 2 {
		t.Fatalf("%d requests", len(f.forms))
	}
	srvForm, mxForm := f.forms[0], f.forms[1]
	for _, k := range []string{"priority", "weight"} {
		if v, ok := srvForm[k]; !ok || v[0] != "0" {
			t.Errorf("SRV %s: %v", k, srvForm[k])
		}
	}
	if srvForm.Get("port") != "443" || srvForm.Get("record-type") != "SRV" || srvForm.Get("host") != "_autodiscover._tcp" {
		t.Errorf("SRV form: %v", srvForm)
	}
	if v, ok := mxForm["priority"]; !ok || v[0] != "0" {
		t.Errorf("MX priority: %v", mxForm["priority"])
	}
	if mxForm.Get("host") != "" || mxForm.Get("auth-password") != "pw" || mxForm.Get("sub-auth-id") != "1" {
		t.Errorf("MX form: %v", mxForm)
	}
	if !strings.HasPrefix(mxForm.Get("record"), "mx.example.com") {
		t.Errorf("MX target: %q", mxForm.Get("record"))
	}
}
