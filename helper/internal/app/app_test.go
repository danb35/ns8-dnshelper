package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
	"github.com/danb35/ns8-dnshelper/helper/internal/fakedns"
	"github.com/danb35/ns8-dnshelper/helper/internal/registry"
	"github.com/danb35/ns8-dnshelper/helper/internal/zonelock"
)

var backend = fakedns.New("example.com.")

func init() {
	registry.Register(registry.Def{
		Name:   "fake",
		Label:  "Fake",
		Fields: []contract.Field{{Name: "token", Secret: true, Required: true}},
		Types:  []string{"TXT"},
		New:    func(map[string]string) any { return backend },
	})
	registry.Register(registry.Def{
		Name:         "fussy",
		Fields:       []contract.Field{{Name: "token", Secret: true, Required: true}},
		TXTForbidden: `"\`,
		New:          func(map[string]string) any { return fakedns.New("example.com.") },
	})
}

func TestProviderTXTLimitationsAreEnforced(t *testing.T) {
	for _, data := range []string{`say "hi"`, `back\slash`} {
		rq := req("append-records", contract.Record{Name: "a", Type: "TXT", Data: data})
		rq.Provider = "fussy"
		r := Run(context.Background(), rq, Options{})
		if r.OK || r.Error.Code != contract.CodeInvalidRequest {
			t.Fatalf("%q: %+v", data, r)
		}
	}
	rq := req("append-records", contract.Record{Name: "a", Type: "TXT", Data: "v=DKIM1; k=rsa; p=abc"})
	rq.Provider = "fussy"
	if r := Run(context.Background(), rq, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func req(op string, recs ...contract.Record) contract.Request {
	return contract.Request{Op: op, Provider: "fake", Zone: "Example.COM.", Credentials: map[string]string{"token": "hunter2-hunter2"}, Records: recs}
}

func TestEndToEndAndResponseIsPureJSON(t *testing.T) {
	ctx := context.Background()
	r := Run(ctx, req("append-records", contract.Record{Name: "@", Type: "TXT", Data: "hello"}), Options{})
	if !r.OK || len(r.Changes.Add) != 1 {
		t.Fatalf("%+v", r)
	}
	r = Run(ctx, req("get-records"), Options{})
	if !r.OK || len(r.Records) != 1 || r.Records[0].Data != "hello" {
		t.Fatalf("%+v", r)
	}
	// Zone is normalized to the form libdns wants.
	if z := backend.Calls[len(backend.Calls)-1].Zone; z != "example.com." {
		t.Fatalf("provider got zone %q", z)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "hunter2") {
		t.Fatal("credential in response")
	}
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		mod  func(*contract.Request)
		code string
	}{
		{"unknown provider", func(r *contract.Request) { r.Provider = "nope" }, contract.CodeUnknownProvider},
		{"unknown op", func(r *contract.Request) { r.Op = "explode" }, contract.CodeInvalidRequest},
		{"bad zone", func(r *contract.Request) { r.Zone = "../etc" }, contract.CodeInvalidRequest},
		{"missing credential", func(r *contract.Request) { r.Credentials = nil }, contract.CodeInvalidRequest},
		{"unknown credential field", func(r *contract.Request) { r.Credentials["bogus"] = "x" }, contract.CodeInvalidRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := req("get-records")
			c.mod(&r)
			resp := Run(ctx, r, Options{})
			if resp.OK || resp.Error == nil || resp.Error.Code != c.code {
				t.Fatalf("%+v", resp)
			}
			if strings.Contains(resp.Error.Message, "hunter2") {
				t.Fatal("credential in error")
			}
			if resp.Records == nil {
				t.Fatal("records must always be an array")
			}
		})
	}
}

func TestListProvidersAndCapabilities(t *testing.T) {
	r := Run(context.Background(), contract.Request{Op: "list-providers"}, Options{})
	names := map[string]bool{}
	for _, p := range r.Providers {
		names[p.Name] = true
	}
	for _, want := range []string{"cloudflare", "corenetworks", "digitalocean", "godaddy", "hetzner", "linode", "namedotcom", "porkbun", "rfc2136", "route53", "fake"} {
		if !names[want] {
			t.Errorf("provider %s missing from %v", want, names)
		}
	}
	r = Run(context.Background(), contract.Request{Op: "capabilities", Provider: "cloudflare"}, Options{})
	if !r.OK || !r.Capabilities.SetRecords || !r.Capabilities.ListZones {
		t.Fatalf("%+v", r)
	}
	r = Run(context.Background(), contract.Request{Op: "capabilities", Provider: "rfc2136"}, Options{})
	if !r.OK || r.Capabilities.ListZones {
		t.Fatalf("rfc2136 has no ListZones: %+v", r)
	}
}

func TestRealProvidersRejectIncompleteCredentialsBeforeAnyNetworkCall(t *testing.T) {
	for _, p := range []string{"cloudflare", "corenetworks", "digitalocean", "godaddy", "hetzner", "linode", "namedotcom", "porkbun", "rfc2136", "route53"} {
		r := Run(context.Background(), contract.Request{Op: "get-records", Provider: p, Zone: "example.com"}, Options{})
		if r.OK || r.Error.Code != contract.CodeInvalidRequest {
			t.Errorf("%s: %+v", p, r)
		}
	}
}

func TestMutationWaitsForTheZoneLock(t *testing.T) {
	dir := t.TempDir()
	release, err := zonelock.Acquire(context.Background(), dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	rq := req("append-records", contract.Record{Name: "x", Type: "TXT", Data: "y"})

	r := Run(context.Background(), rq, Options{LockDir: dir, Timeout: 200 * time.Millisecond})
	if r.OK || r.Error.Code != contract.CodeLocked {
		t.Fatalf("%+v", r)
	}
	// Reads and dry runs do not take the lock.
	if r := Run(context.Background(), req("get-records"), Options{LockDir: dir, Timeout: 200 * time.Millisecond}); !r.OK {
		t.Fatalf("%+v", r)
	}
	rq.DryRun = true
	if r := Run(context.Background(), rq, Options{LockDir: dir, Timeout: 200 * time.Millisecond}); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestRegistrableDomainsNeedsNoProvider(t *testing.T) {
	r := Run(context.Background(), contract.Request{Op: "registrable-domains",
		Names: []string{"mail.example.com", "www.example.com", "nas.lan", "192.168.0.1", "shop.example.org"}}, Options{})
	if !r.OK || len(r.Candidates) != 2 || r.Candidates[0].Zone != "example.com" || len(r.Candidates[0].Names) != 2 {
		t.Fatalf("%+v", r)
	}
	if r := Run(context.Background(), contract.Request{Op: "registrable-domains", Names: make([]string, 5001)}, Options{}); r.OK {
		t.Fatal("an absurd number of names must be refused")
	}
}

func TestListZones(t *testing.T) {
	rq := req("list-zones")
	rq.Zone = "" // list-zones is not about one zone
	r := Run(context.Background(), rq, Options{})
	if !r.OK || len(r.Zones) != 1 || r.Zones[0] != "example.com" {
		t.Fatalf("%+v", r)
	}
	// rfc2136 cannot list zones: that must be reported, not invented.
	r = Run(context.Background(), contract.Request{Op: "list-zones", Provider: "rfc2136",
		Credentials: map[string]string{"server": "127.0.0.1:1", "key_name": "k", "key": "c2VjcmV0"}}, Options{})
	if r.OK || r.Error.Code != contract.CodeUnsupported {
		t.Fatalf("%+v", r)
	}
}

func TestForbiddenCharsNamed(t *testing.T) {
	for set, want := range map[string]string{"\"\\": "a double quote or a backslash", "\\": "a backslash"} {
		if got := forbiddenChars(set); got != want {
			t.Errorf("%q: got %q want %q", set, got, want)
		}
	}
}
