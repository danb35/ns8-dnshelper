package app

// Live tests against real DNS services. They are skipped unless a provider's
// environment variables are set, so `go test ./...` never touches the network.
// Never put tokens or keys in a file.
//
// Cloudflare (optional DNSHELPER_LIVE_CF_ZONE_TOKEN for a separate Zone:Read token):
//
//	DNSHELPER_LIVE_CF_TOKEN=... DNSHELPER_LIVE_CF_ZONE=example.com go test ./internal/app -run Live -v
//
// Hetzner DNS:
//
//	DNSHELPER_LIVE_HETZNER_TOKEN=... DNSHELPER_LIVE_HETZNER_ZONE=example.com go test ...
//
// GoDaddy and name.com:
//
//	DNSHELPER_LIVE_GODADDY_TOKEN=... DNSHELPER_LIVE_GODADDY_ZONE=example.com go test ...
//	(or the legacy DNSHELPER_LIVE_GODADDY_KEY=... DNSHELPER_LIVE_GODADDY_SECRET=... instead of the token)
//	DNSHELPER_LIVE_NAMECOM_USER=... DNSHELPER_LIVE_NAMECOM_TOKEN=... DNSHELPER_LIVE_NAMECOM_ZONE=example.com go test ...
//
// DigitalOcean:
//
//	DNSHELPER_LIVE_DO_TOKEN=... DNSHELPER_LIVE_DO_ZONE=example.com go test ...
//
// Linode:
//
//	DNSHELPER_LIVE_LINODE_TOKEN=... DNSHELPER_LIVE_LINODE_ZONE=example.com go test ...
//
// Core-Networks:
//
//	DNSHELPER_LIVE_CORENETWORKS_LOGIN=... DNSHELPER_LIVE_CORENETWORKS_PASSWORD=... DNSHELPER_LIVE_CORENETWORKS_ZONE=example.com go test ...
//
// Route 53:
//
//	DNSHELPER_LIVE_R53_KEY_ID=... DNSHELPER_LIVE_R53_SECRET=... DNSHELPER_LIVE_R53_ZONE=example.com go test ...
//
// RFC 2136 (see testdata/bind/README.md for a local BIND):
//
//	DNSHELPER_LIVE_RFC2136_SERVER=127.0.0.1:5354 DNSHELPER_LIVE_RFC2136_ZONE=example.test \
//	DNSHELPER_LIVE_RFC2136_KEY_NAME=dnshelper-test DNSHELPER_LIVE_RFC2136_KEY=... go test ...
//
// Every record the tests create is named "_dnshelper-live-<random>-<n>" and is
// deleted afterwards; existing records are only read.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

type live struct {
	t        *testing.T
	provider string
	zone     string
	cred     map[string]string
	prefix   string
}

// liveTarget describes one configured provider, or nil when its variables are unset.
func liveTarget(provider string) (zone string, cred map[string]string) {
	switch provider {
	case "cloudflare":
		tok, zone := os.Getenv("DNSHELPER_LIVE_CF_TOKEN"), os.Getenv("DNSHELPER_LIVE_CF_ZONE")
		if zone == "" {
			zone = os.Getenv("DNSHELPER_LIVE_ZONE") // older name
		}
		if tok == "" || zone == "" {
			return "", nil
		}
		cred = map[string]string{"api_token": tok}
		if zt := os.Getenv("DNSHELPER_LIVE_CF_ZONE_TOKEN"); zt != "" {
			cred["zone_token"] = zt
		}
		return zone, cred
	case "hetzner":
		tok, zone := os.Getenv("DNSHELPER_LIVE_HETZNER_TOKEN"), os.Getenv("DNSHELPER_LIVE_HETZNER_ZONE")
		if tok == "" || zone == "" {
			return "", nil
		}
		return zone, map[string]string{"api_token": tok}
	case "godaddy":
		key, secret, zone := os.Getenv("DNSHELPER_LIVE_GODADDY_KEY"), os.Getenv("DNSHELPER_LIVE_GODADDY_SECRET"), os.Getenv("DNSHELPER_LIVE_GODADDY_ZONE")
		if tok := os.Getenv("DNSHELPER_LIVE_GODADDY_TOKEN"); tok != "" && zone != "" {
			return zone, map[string]string{"api_token": tok}
		}
		if key == "" || secret == "" || zone == "" {
			return "", nil
		}
		return zone, map[string]string{"api_key": key, "api_secret": secret}
	case "namedotcom":
		user, tok, zone := os.Getenv("DNSHELPER_LIVE_NAMECOM_USER"), os.Getenv("DNSHELPER_LIVE_NAMECOM_TOKEN"), os.Getenv("DNSHELPER_LIVE_NAMECOM_ZONE")
		if user == "" || tok == "" || zone == "" {
			return "", nil
		}
		return zone, map[string]string{"user": user, "api_token": tok}
	case "digitalocean":
		tok, zone := os.Getenv("DNSHELPER_LIVE_DO_TOKEN"), os.Getenv("DNSHELPER_LIVE_DO_ZONE")
		if tok == "" || zone == "" {
			return "", nil
		}
		return zone, map[string]string{"api_token": tok}
	case "linode":
		tok, zone := os.Getenv("DNSHELPER_LIVE_LINODE_TOKEN"), os.Getenv("DNSHELPER_LIVE_LINODE_ZONE")
		if tok == "" || zone == "" {
			return "", nil
		}
		return zone, map[string]string{"api_token": tok}
	case "corenetworks":
		login, pw, zone := os.Getenv("DNSHELPER_LIVE_CORENETWORKS_LOGIN"), os.Getenv("DNSHELPER_LIVE_CORENETWORKS_PASSWORD"), os.Getenv("DNSHELPER_LIVE_CORENETWORKS_ZONE")
		if login == "" || pw == "" || zone == "" {
			return "", nil
		}
		return zone, map[string]string{"login": login, "password": pw}
	case "route53":
		id, secret, zone := os.Getenv("DNSHELPER_LIVE_R53_KEY_ID"), os.Getenv("DNSHELPER_LIVE_R53_SECRET"), os.Getenv("DNSHELPER_LIVE_R53_ZONE")
		if id == "" || secret == "" || zone == "" {
			return "", nil
		}
		return zone, map[string]string{"access_key_id": id, "secret_access_key": secret}
	case "rfc2136":
		srv, zone, name, key := os.Getenv("DNSHELPER_LIVE_RFC2136_SERVER"), os.Getenv("DNSHELPER_LIVE_RFC2136_ZONE"),
			os.Getenv("DNSHELPER_LIVE_RFC2136_KEY_NAME"), os.Getenv("DNSHELPER_LIVE_RFC2136_KEY")
		if srv == "" || zone == "" || name == "" || key == "" {
			return "", nil
		}
		cred = map[string]string{"server": srv, "key_name": name, "key": key}
		if alg := os.Getenv("DNSHELPER_LIVE_RFC2136_KEY_ALG"); alg != "" {
			cred["key_alg"] = alg
		}
		return zone, cred
	}
	return "", nil
}

// eachLive runs fn once per provider that has live credentials configured.
func eachLive(t *testing.T, providers []string, fn func(t *testing.T, l *live)) {
	ran := false
	for _, p := range providers {
		zone, cred := liveTarget(p)
		if cred == nil {
			continue
		}
		ran = true
		t.Run(p, func(t *testing.T) {
			var b [4]byte
			_, _ = rand.Read(b[:])
			l := &live{t: t, provider: p, zone: zone, cred: cred, prefix: "_dnshelper-live-" + hex.EncodeToString(b[:])}
			t.Cleanup(l.cleanup)
			fn(t, l)
		})
	}
	if !ran {
		t.Skip("no live provider configured (see the comment at the top of live_test.go)")
	}
}

var (
	cacheOnce sync.Once
	cacheDir  string
)

// liveCacheDir is shared by all the runs of one test binary, as the module's
// state/cache is shared by its runs of the helper, so a provider that limits
// logins is not asked to log in for every call. DNSHELPER_LIVE_CACHE_DIR names it
// (to reuse a token); otherwise it is a temporary directory.
func liveCacheDir() string {
	cacheOnce.Do(func() {
		if d := os.Getenv("DNSHELPER_LIVE_CACHE_DIR"); d != "" {
			cacheDir = d
			return
		}
		cacheDir, _ = os.MkdirTemp("", "dnshelper-live-cache-")
	})
	return cacheDir
}

var allProviders = []string{"cloudflare", "corenetworks", "digitalocean", "godaddy", "hetzner", "linode", "namedotcom", "rfc2136", "route53"}

func (l *live) name(n int) string { return fmt.Sprintf("%s-%d", l.prefix, n) }

// hostName is name without the leading underscore, for A and AAAA records:
// some providers (DigitalOcean) refuse an underscore in a host name.
func (l *live) hostName(n int) string { return strings.TrimPrefix(l.name(n), "_") }

func (l *live) run(op string, mut func(*contract.Request), recs ...contract.Record) contract.Response {
	l.t.Helper()
	rq := contract.Request{Op: op, Provider: l.provider, Zone: l.zone, Credentials: l.cred, Records: recs}
	if mut != nil {
		mut(&rq)
	}
	return Run(context.Background(), rq, Options{LockDir: l.t.TempDir(), CacheDir: liveCacheDir(), Timeout: 120 * time.Second})
}

func (l *live) must(op string, recs ...contract.Record) contract.Response {
	l.t.Helper()
	r := l.run(op, nil, recs...)
	if !r.OK {
		l.t.Fatalf("%s failed: %+v", op, r.Error)
	}
	return r
}

func (l *live) mine() []contract.Record {
	var out []contract.Record
	for _, r := range l.must(contract.OpGetRecords).Records {
		if strings.HasPrefix(r.Name, l.prefix) || strings.HasPrefix(r.Name, strings.TrimPrefix(l.prefix, "_")) {
			out = append(out, r)
		}
	}
	return out
}

func (l *live) cleanup() {
	defer func() {
		if left := l.mine(); len(left) != 0 {
			l.t.Errorf("CLEANUP INCOMPLETE, delete manually: %+v", left)
		}
	}()
	names := map[string]bool{}
	for _, r := range l.mine() {
		names[r.Name] = true
	}
	for n := range names {
		// A name-only delete removes every record at that name; the name is ours.
		if r := l.run(contract.OpDeleteRecords, nil, contract.Record{Name: n}); !r.OK {
			l.t.Errorf("CLEANUP FAILED for %s.%s: %+v", n, l.zone, r.Error)
		}
	}
}

func TestLiveValidate(t *testing.T) {
	eachLive(t, allProviders, func(t *testing.T, l *live) {
		r := l.must(contract.OpValidate)
		t.Logf("validate: method=%s capabilities=%+v", r.Validation.Method, *r.Capabilities)
		w := l.run(contract.OpValidate, func(q *contract.Request) { q.WriteTest = true })
		if !w.OK || w.Validation.WriteTest != "passed" {
			t.Fatalf("write test: %+v %+v", w.Error, w.Validation)
		}
		for _, rec := range l.must(contract.OpGetRecords).Records {
			if strings.HasPrefix(rec.Name, "_dnshelper-test-") {
				t.Fatalf("write test left %s behind", rec.Name)
			}
		}
	})
}

func TestLiveBadCredentialsCloudflare(t *testing.T) {
	eachLive(t, []string{"cloudflare"}, func(t *testing.T, l *live) {
		r := l.run(contract.OpValidate, func(q *contract.Request) {
			q.Credentials = map[string]string{"api_token": "0123456789-not-a-real-token-0123456789abcd"}
		})
		if r.OK || r.Error.Code != contract.CodeAuthFailed {
			t.Fatalf("want auth_failed, got ok=%v err=%+v", r.OK, r.Error)
		}
		if strings.Contains(r.Error.Message, "not-a-real") {
			t.Fatal("token echoed")
		}
	})
}

func TestLiveBadCredentialsHetzner(t *testing.T) {
	eachLive(t, []string{"hetzner"}, func(t *testing.T, l *live) {
		r := l.run(contract.OpValidate, func(q *contract.Request) {
			q.Credentials = map[string]string{"api_token": "0123456789-not-a-real-token-0123456789abcd"}
		})
		t.Logf("bad token gives ok=%v err=%+v", r.OK, r.Error)
		if r.OK {
			t.Fatal("a bad token must not validate")
		}
		if strings.Contains(fmt.Sprint(r.Error), "not-a-real") {
			t.Fatal("token echoed")
		}
	})
}

func TestLiveBadCredentialsDigitalOcean(t *testing.T) {
	eachLive(t, []string{"digitalocean"}, func(t *testing.T, l *live) {
		r := l.run(contract.OpValidate, func(q *contract.Request) {
			q.Credentials = map[string]string{"api_token": "dop_v1_0123456789-not-a-real-token-0123456789abcd"}
		})
		if r.OK || r.Error.Code != contract.CodeAuthFailed {
			t.Fatalf("want auth_failed, got ok=%v err=%+v", r.OK, r.Error)
		}
		if strings.Contains(fmt.Sprint(r.Error), "not-a-real") {
			t.Fatal("token echoed")
		}
	})
}

func TestLiveBadCredentialsLinode(t *testing.T) {
	eachLive(t, []string{"linode"}, func(t *testing.T, l *live) {
		r := l.run(contract.OpValidate, func(q *contract.Request) {
			q.Credentials = map[string]string{"api_token": "0123456789not-a-real-token0123456789abcdef0123456789abcdef012"}
		})
		if r.OK || r.Error.Code != contract.CodeAuthFailed {
			t.Fatalf("want auth_failed, got ok=%v err=%+v", r.OK, r.Error)
		}
		if strings.Contains(fmt.Sprint(r.Error), "not-a-real") {
			t.Fatal("token echoed")
		}
	})
}

func TestLiveBadCredentialsRoute53(t *testing.T) {
	eachLive(t, []string{"route53"}, func(t *testing.T, l *live) {
		r := l.run(contract.OpValidate, func(q *contract.Request) {
			q.Credentials = map[string]string{"access_key_id": l.cred["access_key_id"], "secret_access_key": "not-the-secret-0123456789abcdefghijklmnop"}
		})
		if r.OK || r.Error.Code != contract.CodeAuthFailed {
			t.Fatalf("want auth_failed, got ok=%v err=%+v", r.OK, r.Error)
		}
		if strings.Contains(fmt.Sprint(r.Error), "not-the-secret") {
			t.Fatal("secret echoed")
		}
	})
}

func TestLiveBadCredentialsCoreNetworks(t *testing.T) {
	eachLive(t, []string{"corenetworks"}, func(t *testing.T, l *live) {
		r := l.run(contract.OpValidate, func(q *contract.Request) {
			q.Credentials = map[string]string{"login": l.cred["login"], "password": "not-the-password-0123456789"}
		})
		if r.OK || r.Error.Code != contract.CodeAuthFailed {
			t.Fatalf("want auth_failed, got ok=%v err=%+v", r.OK, r.Error)
		}
		if strings.Contains(fmt.Sprint(r.Error), "not-the-password") {
			t.Fatal("password echoed")
		}
	})
}

func TestLiveBadCredentialsRFC2136(t *testing.T) {
	eachLive(t, []string{"rfc2136"}, func(t *testing.T, l *live) {
		r := l.run(contract.OpValidate, func(q *contract.Request) {
			q.Credentials = map[string]string{"server": l.cred["server"], "key_name": l.cred["key_name"], "key_alg": "hmac-sha256",
				"key": "d3JvbmcgcGFzc3dvcmQgd3JvbmcgcGFzc3dvcmQ="}
		})
		t.Logf("wrong TSIG key gives ok=%v err=%+v", r.OK, r.Error)
		if r.OK {
			t.Fatal("a wrong TSIG key must not validate")
		}
		if strings.Contains(fmt.Sprint(r.Error), "d3JvbmcgcGFzc3dvcmQ") {
			t.Fatal("key echoed")
		}
	})
}

func TestLiveWrongZone(t *testing.T) {
	eachLive(t, allProviders, func(t *testing.T, l *live) {
		r := l.run(contract.OpValidate, func(q *contract.Request) { q.Zone = "dnshelper-no-such-zone.invalid" })
		if r.OK {
			t.Fatal("validate must fail for a zone the credentials cannot see")
		}
		t.Logf("wrong zone gives code=%s", r.Error.Code)
	})
}

func TestLiveLongTXTRoundTrip(t *testing.T) {
	eachLive(t, allProviders, func(t *testing.T, l *live) {
		dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 12)
		l.must(contract.OpAppendRecords, contract.Record{Name: l.name(1), Type: "TXT", TTL: 120, Data: dkim})
		got := l.mine()
		if len(got) != 1 || got[0].Data != dkim {
			t.Fatalf("round trip changed a %d-byte value: %+v", len(dkim), got)
		}
		odd := "v=spf1 include:a.example.net; note=x  end"
		l.must(contract.OpAppendRecords, contract.Record{Name: l.name(2), Type: "TXT", TTL: 120, Data: odd})
		for _, r := range l.mine() {
			if r.Name == l.name(2) && r.Data != odd {
				t.Fatalf("odd TXT came back as %q", r.Data)
			}
		}
	})
}

func TestLiveTXTQuotesAndBackslashes(t *testing.T) {
	eachLive(t, allProviders, func(t *testing.T, l *live) {
		v := `a "quoted" word and a back\slash`
		r := l.run(contract.OpAppendRecords, nil, contract.Record{Name: l.name(1), Type: "TXT", TTL: 120, Data: v})
		if !r.OK {
			if r.Error.Code != contract.CodeInvalidRequest {
				t.Fatalf("%+v", r.Error)
			}
			t.Logf("refused: %s", r.Error.Message)
			return
		}
		if got := l.mine(); len(got) != 1 || got[0].Data != v {
			t.Fatalf("a provider that accepts quotes must round-trip them: %+v", got)
		}
	})
}

func TestLiveCNAMEConflictsAndRecordTypes(t *testing.T) {
	eachLive(t, allProviders, func(t *testing.T, l *live) {
		l.must(contract.OpAppendRecords, contract.Record{Name: l.hostName(1), Type: "A", TTL: 120, Data: "192.0.2.10"})
		if r := l.run(contract.OpAppendRecords, nil, contract.Record{Name: l.hostName(1), Type: "CNAME", Data: "example.net."}); r.OK || r.Error.Code != contract.CodeConflict {
			t.Fatalf("CNAME beside A must be refused: %+v", r)
		}
		l.must(contract.OpAppendRecords, contract.Record{Name: l.name(2), Type: "CNAME", TTL: 120, Data: "target.example.net."})
		l.must(contract.OpAppendRecords, contract.Record{Name: l.name(3) + "._tcp", Type: "SRV", TTL: 120, Data: "10 5 5060 sip.example.net."})
		l.must(contract.OpAppendRecords, contract.Record{Name: l.name(4), Type: "MX", TTL: 120, Data: "10 mail.example.net."})
		// Issue #19: zero priority and weight, as ns8-automx's _autodiscover._tcp.
		l.must(contract.OpAppendRecords, contract.Record{Name: l.name(6) + "._tcp", Type: "SRV", TTL: 120, Data: "0 0 443 mail.example.net."})
		l.must(contract.OpAppendRecords, contract.Record{Name: l.hostName(5), Type: "AAAA", TTL: 120, Data: "2001:db8::1"})
		seen := map[string]string{}
		for _, r := range l.mine() {
			if r.Name == l.name(6)+"._tcp" {
				if got := strings.TrimSuffix(r.Data, "."); got != "0 0 443 mail.example.net" {
					t.Errorf("zero SRV: got %q", r.Data)
				}
				continue
			}
			seen[r.Type] = r.Data
		}
		for typ, want := range map[string]string{"A": "192.0.2.10", "CNAME": "target.example.net", "SRV": "10 5 5060 sip.example.net", "MX": "10 mail.example.net", "AAAA": "2001:db8::1"} {
			if got := strings.TrimSuffix(seen[typ], "."); got != want {
				t.Errorf("%s: got %q want %q", typ, seen[typ], want)
			}
		}
	})
}

func TestLiveSetMergeAndExactDelete(t *testing.T) {
	eachLive(t, allProviders, func(t *testing.T, l *live) {
		n := l.name(1)
		l.must(contract.OpAppendRecords,
			contract.Record{Name: n, Type: "TXT", TTL: 120, Data: "site-verification=abc"},
			contract.Record{Name: n, Type: "TXT", TTL: 120, Data: "v=spf1 include:old.example.net -all"})

		r := l.run(contract.OpSetRecords, func(q *contract.Request) { q.ReplacePrefixes = []string{"v=spf1"} },
			contract.Record{Name: n, Type: "TXT", TTL: 120, Data: "v=spf1 include:new.example.net -all"})
		if !r.OK {
			t.Fatalf("%+v", r.Error)
		}
		var data []string
		for _, x := range l.mine() {
			data = append(data, x.Data)
		}
		if len(data) != 2 || !(contains(data, "site-verification=abc") && contains(data, "v=spf1 include:new.example.net -all")) {
			t.Fatalf("merge went wrong: %v", data)
		}

		if r := l.must(contract.OpDeleteRecords, contract.Record{Name: n, Type: "TXT", Data: "nope"}); len(r.Changes.Remove) != 0 {
			t.Fatalf("inexact delete removed %+v", r.Changes.Remove)
		}
		l.must(contract.OpDeleteRecords, contract.Record{Name: n, Type: "TXT", Data: "site-verification=abc"})
		if got := l.mine(); len(got) != 1 || !strings.HasPrefix(got[0].Data, "v=spf1") {
			t.Fatalf("after exact delete: %+v", got)
		}
	})
}

// The mail-module use case: replace a DKIM key that is longer than one TXT string.
func TestLiveReplaceLongDKIM(t *testing.T) {
	eachLive(t, allProviders, func(t *testing.T, l *live) {
		n := l.name(1)
		old := "v=DKIM1; k=rsa; p=" + strings.Repeat("OLDKEY0123456789", 26)
		new := "v=DKIM1; k=rsa; p=" + strings.Repeat("NEWKEY0123456789", 26)
		l.must(contract.OpAppendRecords, contract.Record{Name: n, Type: "TXT", TTL: 120, Data: old})
		r := l.run(contract.OpSetRecords, func(q *contract.Request) { q.ReplacePrefixes = []string{"v=DKIM1"} },
			contract.Record{Name: n, Type: "TXT", TTL: 120, Data: new})
		if !r.OK {
			t.Fatalf("%+v", r.Error)
		}
		if got := l.mine(); len(got) != 1 || got[0].Data != new {
			t.Fatalf("replace went wrong: %+v", got)
		}
		l.must(contract.OpDeleteRecords, contract.Record{Name: n, Type: "TXT", Data: new})
		if got := l.mine(); len(got) != 0 {
			t.Fatalf("long value not deleted: %+v", got)
		}
	})
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
