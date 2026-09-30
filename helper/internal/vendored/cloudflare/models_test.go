package cloudflare

// Regression test for the local PATCH in models.go: a zero priority/weight
// must still reach Cloudflare's API as an explicit 0, not be dropped by
// encoding/json's omitempty. Reproduces the exact failure seen live,
// 2026-09-23, creating ns8-automx's _autodiscover._tcp SRV 0 0 443 <target>
// record: Cloudflare answered 400 "weight is a required data field" because
// the un-patched upstream struct silently omitted it.

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

func TestCloudflareRecordSendsZeroPriorityAndWeight(t *testing.T) {
	srv := libdns.SRV{
		Service:   "autodiscover",
		Transport: "tcp",
		Name:      "@",
		Priority:  0,
		Weight:    0,
		Port:      443,
		Target:    "ns8.example.com.",
	}
	rec, err := cloudflareRecord(srv)
	if err != nil {
		t.Fatalf("cloudflareRecord: %v", err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	body := string(b)
	for _, want := range []string{`"weight":0`, `"priority":0`, `"port":443`} {
		if !strings.Contains(body, want) {
			t.Errorf("request body missing %s (omitted by encoding/json's omitempty): %s", want, body)
		}
	}
}

// The top-level priority (MX preference) must be sent as an explicit 0 too:
// Cloudflare answered 400 "priority is a required field" without it, live,
// 2026-09-30. Checked on the top-level key, since the SRV patch above makes
// data.priority appear in every body.
func TestCloudflareRecordSendsZeroMXPreference(t *testing.T) {
	rec, err := cloudflareRecord(libdns.MX{Name: "@", Preference: 0, Target: "mail.example.com."})
	if err != nil {
		t.Fatalf("cloudflareRecord: %v", err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if top["priority"] != float64(0) {
		t.Errorf(`request body missing top-level "priority":0: %s`, b)
	}
}

// Record types without a top-level priority must not gain one.
func TestCloudflareRecordOmitsPriorityForOtherTypes(t *testing.T) {
	rec, err := cloudflareRecord(libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.1")})
	if err != nil {
		t.Fatalf("cloudflareRecord: %v", err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := top["priority"]; ok {
		t.Errorf("request body has a spurious top-level priority: %s", b)
	}
}
