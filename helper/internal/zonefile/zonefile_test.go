package zonefile

import (
	"errors"
	"strings"
	"testing"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

func rec(name, typ string, ttl int64, data string) contract.Record {
	return contract.Record{Name: name, Type: typ, TTL: ttl, Data: data}
}

func TestExportThenParseRoundTrips(t *testing.T) {
	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 12) // over 255 bytes
	in := []contract.Record{
		rec("@", "SOA", 3600, "ns1.example.com. hostmaster.example.com. 1 10800 3600 604800 3600"),
		rec("@", "NS", 3600, "ns1.example.com."),
		rec("@", "MX", 300, "10 mail.example.com."),
		rec("@", "TXT", 300, "v=spf1 mx -all"),
		rec("mail._domainkey", "TXT", 300, dkim),
		rec("q", "TXT", 0, `say "hi" back\slash café`),
		rec("www", "CNAME", 60, "web.example.net."),
		rec("_imaps._tcp", "SRV", 300, "0 0 993 mail.example.com."),
		rec("@", "CAA", 300, `0 issue "letsencrypt.org"`),
		rec("sub", "NS", 300, "ns1.other.example."),
		rec("v6", "AAAA", 300, "2001:db8::1"),
	}
	text := Export("example.com", in)
	if !strings.Contains(text, "$ORIGIN example.com.\n") {
		t.Fatalf("no $ORIGIN:\n%s", text)
	}
	if strings.Index(text, "SOA") > strings.Index(text, "MX") {
		t.Errorf("SOA should come first:\n%s", text)
	}
	out, skipped, err := Parse("example.com", text)
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if len(skipped) != 2 || skipped[0].Type != "SOA" || skipped[1].Type != "NS" || skipped[1].Name != "@" {
		t.Errorf("skipped: %+v", skipped)
	}
	want := map[string]contract.Record{}
	for _, r := range in[2:] {
		want[r.Name+" "+r.Type] = r
	}
	if len(out) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(out), len(want), out)
	}
	for _, r := range out {
		w, ok := want[r.Name+" "+r.Type]
		if !ok || r.Data != w.Data {
			t.Errorf("%s %s: got %q, want %q", r.Name, r.Type, r.Data, w.Data)
		}
		if w.TTL != 0 && r.TTL != w.TTL {
			t.Errorf("%s %s: TTL %d, want %d", r.Name, r.Type, r.TTL, w.TTL)
		}
		if w.TTL == 0 && r.TTL != DefaultTTL {
			t.Errorf("%s %s: no TTL should read back as $TTL, got %d", r.Name, r.Type, r.TTL)
		}
	}
	if !strings.Contains(text, `caf\195\169"`) {
		t.Errorf("non-ASCII bytes should be written as \\DDD:\n%s", text)
	}
}

func TestParseOfAZoneFileFromElsewhere(t *testing.T) {
	text := `; from another DNS host
$ORIGIN example.com.
$TTL 600
@   IN SOA ns1 hostmaster 2026110601 3600 600 1209600 300
    IN NS  ns1
    IN NS  ns2.example.net.
    IN MX  10 mail          ; relative target
mail      IN A    192.0.2.25
www.example.com. 120 IN CNAME mail
long  IN TXT "first part " "second part"
other.example.org. IN A 192.0.2.1
chaos CH TXT "x"
`
	out, skipped, err := Parse("Example.COM.", text)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range out {
		got[r.Name+" "+r.Type] = r.Data
	}
	for k, v := range map[string]string{
		"@ MX":      "10 mail.example.com.",
		"mail A":    "192.0.2.25",
		"www CNAME": "mail.example.com.",
		"long TXT":  "first part second part",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.Name+" "+s.Type] = s.Reason
	}
	for _, k := range []string{"@ SOA", "@ NS", "other.example.org A", "chaos TXT"} {
		if reasons[k] == "" {
			t.Errorf("%s should be skipped: %+v", k, skipped)
		}
	}
}

func TestParseRefusesIncludeAndReportsErrors(t *testing.T) {
	for _, text := range []string{
		"$INCLUDE /etc/passwd\n",
		"www IN CNAME\n",
		"www IN A 999.1.1.1\n",
	} {
		_, _, err := Parse("example.com", text)
		var ce *contract.Error
		if !errors.As(err, &ce) || ce.Code != contract.CodeInvalidRequest {
			t.Errorf("%q: want invalid_request, got %v", text, err)
		}
	}
	if _, _, err := Parse("example.com", strings.Repeat(";", MaxBytes+1)); err == nil {
		t.Error("an oversized file must be refused")
	}
	out, skipped, err := Parse("example.com", "")
	if err != nil || len(out) != 0 || len(skipped) != 0 {
		t.Errorf("empty file: %v %v %v", out, skipped, err)
	}
}
