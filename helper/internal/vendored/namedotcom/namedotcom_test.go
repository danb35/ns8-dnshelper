package namedotcom

// Regression test for the local PATCH in namedotcom.go: an SRV or MX record
// with a legitimately zero priority (the common case for SRV) must still
// reach name.com's API as an explicit 0, not be dropped by encoding/json's
// omitempty on a plain int32. Found by code audit after the matching, live-
// confirmed libdns/cloudflare bug, 2026-09-23 -- not independently confirmed
// against the live name.com API.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

func TestFromLibDNSRecordSendsZeroSRVPriority(t *testing.T) {
	var rec nameDotComRecord
	rec.fromLibDNSRecord(0, libdns.RR{
		Name: "_autodiscover._tcp",
		Type: "SRV",
		Data: "0 0 443 ns8.example.com.",
	}, "example.com")

	if rec.Priority == nil {
		t.Fatal("Priority is nil; a real, explicit zero priority was lost")
	}
	if *rec.Priority != 0 {
		t.Fatalf("Priority = %d, want 0", *rec.Priority)
	}

	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"priority":0`) {
		t.Errorf(`request body missing "priority":0 (omitted by encoding/json's omitempty): %s`, b)
	}
}

// A record type that genuinely has no priority (e.g. A) must still omit the
// field, exactly as before the patch -- the fix must not send a spurious
// "priority":0 for record types that never had one.
func TestFromLibDNSRecordOmitsPriorityForOtherTypes(t *testing.T) {
	var rec nameDotComRecord
	rec.fromLibDNSRecord(0, libdns.RR{Name: "www", Type: "A", Data: "203.0.113.1"}, "example.com")

	if rec.Priority != nil {
		t.Fatalf("Priority = %v, want nil for a record type with no priority", *rec.Priority)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(b), `"priority"`) {
		t.Errorf("request body has a spurious priority field: %s", b)
	}
}
