package cloudflare

// Regression test for the local PATCH in models.go: a zero priority/weight
// must still reach Cloudflare's API as an explicit 0, not be dropped by
// encoding/json's omitempty. Reproduces the exact failure seen live,
// 2026-09-23, creating ns8-automx's _autodiscover._tcp SRV 0 0 443 <target>
// record: Cloudflare answered 400 "weight is a required data field" because
// the un-patched upstream struct silently omitted it.

import (
	"encoding/json"
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
