package dnsops

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
	"github.com/danb35/ns8-dnshelper/helper/internal/fakedns"
)

const zone = "example.com"

func rec(name, typ, data string) contract.Record {
	return contract.Record{Name: name, Type: typ, Data: data}
}

func newOps(f *fakedns.Fake) *Ops { return &Ops{Provider: f, Zone: zone} }

func txt(name, text string) libdns.Record {
	return libdns.TXT{Name: name, TTL: 300 * time.Second, Text: text}
}

// ok unwraps a (Response, error) call result, failing the test on error:
// ok(t)(o.GetRecords(ctx, nil)).
func ok(t *testing.T) func(contract.Response, error) contract.Response {
	return func(r contract.Response, err error) contract.Response {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return r
	}
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var ce *contract.Error
	if !errors.As(err, &ce) || ce.Code != code {
		t.Fatalf("want error code %q, got %v", code, err)
	}
}

func dataOf(rs []contract.Record) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Name+" "+r.Type+" "+r.Data)
	}
	return out
}

func TestLongTXTIsPassedWholeAndChunkedByTheProvider(t *testing.T) {
	// A 2048-bit DKIM public key record is about 400 bytes.
	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 12)
	if len(dkim) <= 255 {
		t.Fatal("test value must exceed one TXT string")
	}
	f := fakedns.New(zone)
	o := newOps(f)
	ok(t)(o.AppendRecords(context.Background(), []contract.Record{rec("mail._domainkey", "TXT", dkim)}, false))

	// The fake, like a real provider, split it...
	if got := f.Chunks("mail._domainkey"); len(got) != 1 || got[0] != 2 {
		t.Fatalf("provider should have stored 2 strings, got %v", got)
	}
	// ...but the caller sees one unquoted string again.
	r := ok(t)(o.GetRecords(context.Background(), &contract.Filter{Name: "mail._domainkey"}))
	if len(r.Records) != 1 || r.Records[0].Data != dkim {
		t.Fatalf("round trip changed the value: %+v", r.Records)
	}
	// And it is handed to the provider unsplit and unquoted.
	var appendCall fakedns.Call
	for _, c := range f.Calls {
		if c.Op == "append" {
			appendCall = c
		}
	}
	if got := appendCall.Records[0].RR().Data; got != dkim {
		t.Fatalf("provider received a modified value: %q", got)
	}
}

func TestQuotedTXTIsRejected(t *testing.T) {
	_, err := newOps(fakedns.New(zone)).AppendRecords(context.Background(), []contract.Record{rec("@", "TXT", `"v=spf1 -all"`)}, false)
	wantCode(t, err, contract.CodeInvalidRequest)
}

func TestNamesMustBeRelative(t *testing.T) {
	for _, n := range []string{"www.example.com", "example.com", "www.", ""} {
		_, err := newOps(fakedns.New(zone)).AppendRecords(context.Background(), []contract.Record{rec(n, "A", "192.0.2.1")}, true)
		wantCode(t, err, contract.CodeInvalidRequest)
	}
}

func TestCNAMEConflicts(t *testing.T) {
	ctx := context.Background()
	newFake := func() *fakedns.Fake {
		f := fakedns.New(zone)
		f.Seed(libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.1")},
			libdns.CNAME{Name: "alias", Target: "www.example.com."})
		return f
	}
	cases := []struct {
		name string
		call func(o *Ops) error
	}{
		{"CNAME over existing A", func(o *Ops) error {
			_, err := o.AppendRecords(ctx, []contract.Record{rec("www", "CNAME", "other.example.net.")}, false)
			return err
		}},
		{"A next to existing CNAME", func(o *Ops) error {
			_, err := o.AppendRecords(ctx, []contract.Record{rec("alias", "A", "192.0.2.9")}, false)
			return err
		}},
		{"CNAME at apex", func(o *Ops) error {
			_, err := o.AppendRecords(ctx, []contract.Record{rec("@", "CNAME", "www.example.com.")}, false)
			return err
		}},
		{"two CNAMEs in one request", func(o *Ops) error {
			_, err := o.AppendRecords(ctx, []contract.Record{rec("x", "CNAME", "a.example.net."), rec("x", "CNAME", "b.example.net.")}, false)
			return err
		}},
		{"set CNAME where TXT exists", func(o *Ops) error {
			_, err := o.SetRecords(ctx, []contract.Record{rec("www", "CNAME", "a.example.net.")}, "", nil, false)
			return err
		}},
		{"SRV target is a CNAME", func(o *Ops) error {
			_, err := o.AppendRecords(ctx, []contract.Record{rec("_sip._tcp", "SRV", "10 5 5060 alias.example.com.")}, false)
			return err
		}},
		{"MX target is a CNAME", func(o *Ops) error {
			_, err := o.AppendRecords(ctx, []contract.Record{rec("@", "MX", "10 alias.example.com.")}, false)
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			wantCode(t, c.call(newOps(f)), contract.CodeConflict)
			for _, op := range f.Ops() {
				if op != "get" {
					t.Fatalf("a conflicting request must not write, calls: %v", f.Ops())
				}
			}
		})
	}
}

func TestExistingProblemsElsewhereDoNotBlockUnrelatedChanges(t *testing.T) {
	f := fakedns.New(zone)
	f.Seed(libdns.CNAME{Name: "bad", Target: "a.example.net."}, libdns.TXT{Name: "bad", Text: "already broken"})
	_, err := newOps(f).AppendRecords(context.Background(), []contract.Record{rec("ok", "TXT", "fine")}, false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAppendIsIdempotentAndDryRunWritesNothing(t *testing.T) {
	ctx := context.Background()
	f := fakedns.New(zone)
	o := newOps(f)
	in := []contract.Record{rec("@", "TXT", "site-verification=abc")}

	r := ok(t)(o.AppendRecords(ctx, in, true))
	if !r.DryRun || len(r.Changes.Add) != 1 {
		t.Fatalf("dry run should report one addition: %+v", r)
	}
	if got := f.Ops(); len(got) != 1 || got[0] != "get" {
		t.Fatalf("dry run must only read, calls: %v", got)
	}
	ok(t)(o.AppendRecords(ctx, in, false))
	r = ok(t)(o.AppendRecords(ctx, in, false))
	if len(r.Changes.Add) != 0 {
		t.Fatalf("second append should be a no-op: %+v", r.Changes)
	}
	all := ok(t)(o.GetRecords(ctx, nil))
	if len(all.Records) != 1 {
		t.Fatalf("want 1 record, got %v", dataOf(all.Records))
	}
}

func apexZone() *fakedns.Fake {
	f := fakedns.New(zone)
	f.Seed(
		txt("@", "site-verification=abc"),
		txt("@", "v=spf1 include:old.example.net -all"),
		libdns.NS{Name: "@", Target: "ns1.example.net."},
	)
	return f
}

func TestSetRecordsMergeKeepsOtherApexTXT(t *testing.T) {
	ctx := context.Background()
	f := apexZone()
	o := newOps(f)
	spf := rec("@", "TXT", "v=spf1 include:new.example.net -all")

	r := ok(t)(o.SetRecords(ctx, []contract.Record{spf}, "", []string{"v=spf1"}, false))
	if len(r.Changes.Add) != 1 || len(r.Changes.Remove) != 1 || !strings.HasPrefix(r.Changes.Remove[0].Data, "v=spf1") {
		t.Fatalf("expected the old SPF to be replaced: %+v", r.Changes)
	}
	all := ok(t)(o.GetRecords(ctx, &contract.Filter{Type: "TXT"}))
	got := dataOf(all.Records)
	if len(got) != 2 || !contains2(got, "@ TXT site-verification=abc") || !contains2(got, "@ TXT "+spf.Data) {
		t.Fatalf("merge must keep the verification record and hold the new SPF, got %v", got)
	}
	// The apex NS is untouched.
	if ns := ok(t)(o.GetRecords(ctx, &contract.Filter{Type: "NS"})); len(ns.Records) != 1 {
		t.Fatal("apex NS was disturbed")
	}
}

func contains2(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestSetRecordsMergeWithoutPrefixAddsAlongside(t *testing.T) {
	ctx := context.Background()
	f := apexZone()
	r := ok(t)(newOps(f).SetRecords(ctx, []contract.Record{rec("@", "TXT", "another=1")}, contract.ModeMerge, nil, false))
	if len(r.Changes.Remove) != 0 || len(r.Changes.Add) != 1 {
		t.Fatalf("%+v", r.Changes)
	}
	// Applied as an append of just the new record: the existing members are
	// never rewritten.
	if ops := f.Ops(); len(ops) != 2 || ops[1] != "append" {
		t.Fatalf("calls: %v", ops)
	}
	if got := len(ok(t)(newOps(f).GetRecords(ctx, &contract.Filter{Type: "TXT"})).Records); got != 3 {
		t.Fatalf("want 3 TXT records, got %d", got)
	}
}

func TestSetRecordsAppliesAsDeleteThenAppendWithProviderRecords(t *testing.T) {
	f := apexZone()
	ok(t)(newOps(f).SetRecords(context.Background(), []contract.Record{rec("@", "TXT", "v=spf1 -all")}, "", []string{"v=spf1"}, false))
	ops := f.Ops()
	// get, delete, get (verify the delete), append
	if len(ops) != 4 || ops[1] != "delete" || ops[2] != "get" || ops[3] != "append" {
		t.Fatalf("calls: %v", ops)
	}
	del := f.Calls[1]
	if len(del.Records) != 1 || del.Records[0].(libdns.TXT).ProviderData == nil {
		t.Fatalf("delete must be handed the provider's own record: %+v", del.Records)
	}
}

func TestSetRecordsFallsBackToSetWhenProviderCannotDeleteOrAppend(t *testing.T) {
	f := apexZone()
	o := &Ops{Provider: fakedns.SetOnly{F: f}, Zone: zone}
	ok(t)(o.SetRecords(context.Background(), []contract.Record{rec("@", "TXT", "another=1")}, contract.ModeMerge, nil, false))
	set := f.Calls[len(f.Calls)-1]
	if set.Op != "set" || len(set.Records) != 3 {
		t.Fatalf("SetRecords should get the full merged RRset, got %d records in %q", len(set.Records), set.Op)
	}
	for _, kept := range set.Records[:2] {
		if kept.(libdns.TXT).ProviderData == nil {
			t.Fatal("kept records must be passed through as the provider returned them")
		}
	}
}

func TestSetRecordsRestoresRemovedRecordsWhenAppendFails(t *testing.T) {
	ctx := context.Background()
	f := apexZone()
	o := newOps(f)
	before := len(ok(t)(o.GetRecords(ctx, &contract.Filter{Type: "TXT"})).Records)
	// The first append fails; the restore append that follows succeeds.
	failing := &failOnce{Fake: f, op: "append"}
	o = &Ops{Provider: failing, Zone: zone}
	_, err := o.SetRecords(ctx, []contract.Record{rec("@", "TXT", "v=spf1 -all")}, "", []string{"v=spf1"}, false)
	wantCode(t, err, contract.CodeProviderError)
	if !strings.Contains(err.Error(), "left unchanged") {
		t.Fatalf("error should say the zone was restored: %v", err)
	}
	got := ok(t)(newOps(f).GetRecords(ctx, &contract.Filter{Type: "TXT"})).Records
	if len(got) != before {
		t.Fatalf("zone not restored: %v", dataOf(got))
	}
}

// failOnce fails the first call of one operation and then behaves normally.
type failOnce struct {
	*fakedns.Fake
	op   string
	done bool
}

func (p *failOnce) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if !p.done {
		p.done = true
		return nil, errors.New("boom")
	}
	return p.Fake.AppendRecords(ctx, zone, recs)
}

func TestChunkedTXTFromProviderIsRejoinedForCallersButDeletableAsIs(t *testing.T) {
	ctx := context.Background()
	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 12)
	f := fakedns.New(zone)
	f.QuoteChunks = true // reads look like `<255>" "<rest>`, as Cloudflare's do
	o := newOps(f)
	ok(t)(o.AppendRecords(ctx, []contract.Record{rec("mail._domainkey", "TXT", dkim)}, false))

	got := ok(t)(o.GetRecords(ctx, nil)).Records
	if len(got) != 1 || got[0].Data != dkim {
		t.Fatalf("caller must see the plain value, got %q", got[0].Data)
	}
	// Appending the same value again is recognised as already present.
	if r := ok(t)(o.AppendRecords(ctx, []contract.Record{rec("mail._domainkey", "TXT", dkim)}, false)); len(r.Changes.Add) != 0 {
		t.Fatalf("duplicate not recognised: %+v", r.Changes)
	}
	// Delete by the plain value: the provider is handed its own (chunked) text.
	ok(t)(o.DeleteRecords(ctx, []contract.Record{rec("mail._domainkey", "TXT", dkim)}, false))
	var del fakedns.Call
	for _, c := range f.Calls {
		if c.Op == "delete" {
			del = c
		}
	}
	if !strings.Contains(del.Records[0].RR().Data, `" "`) {
		t.Fatalf("provider should get its own chunked form back: %q", del.Records[0].RR().Data)
	}
	if left := ok(t)(o.GetRecords(ctx, nil)).Records; len(left) != 0 {
		t.Fatalf("not deleted: %v", dataOf(left))
	}
}

func TestRejoinTXTOnlyAtExactChunkBoundaries(t *testing.T) {
	a, b := strings.Repeat("a", 255), "rest"
	if got := rejoinTXT(a + `" "` + b); got != a+b {
		t.Fatal("chunk boundary not rejoined")
	}
	for _, s := range []string{
		`say " " twice`,
		"short" + `" "` + b,
		a + `" "` + a + `" "` + b + `" "` + "x", // a short string in the middle: not chunking
	} {
		if rejoinTXT(s) != s {
			t.Fatalf("value %q must be left alone", s)
		}
	}
	if got := rejoinTXT(a + `" "` + a + `" "` + b); got != a+a+b {
		t.Fatal("three-chunk value not rejoined")
	}
}

func TestSetRecordsRRsetModeReplacesAndDryRunShowsIt(t *testing.T) {
	ctx := context.Background()
	f := apexZone()
	o := newOps(f)
	in := []contract.Record{rec("@", "TXT", "only=me")}

	r := ok(t)(o.SetRecords(ctx, in, contract.ModeRRset, nil, true))
	if len(r.Changes.Remove) != 2 || len(r.Changes.Add) != 1 {
		t.Fatalf("preview should show both existing TXT records going: %+v", r.Changes)
	}
	if len(ok(t)(o.GetRecords(ctx, &contract.Filter{Type: "TXT"})).Records) != 2 {
		t.Fatal("dry run modified the zone")
	}
	ok(t)(o.SetRecords(ctx, in, contract.ModeRRset, nil, false))
	if got := dataOf(ok(t)(o.GetRecords(ctx, &contract.Filter{Type: "TXT"})).Records); len(got) != 1 {
		t.Fatalf("rrset mode should leave only the input, got %v", got)
	}
}

func TestSetRecordsNoChangeMakesNoWriteAndKeepsTTL(t *testing.T) {
	f := apexZone()
	r := ok(t)(newOps(f).SetRecords(context.Background(), []contract.Record{rec("@", "TXT", "site-verification=abc")}, "", nil, false))
	if !(len(r.Changes.Add) == 0 && len(r.Changes.Remove) == 0) {
		t.Fatalf("%+v", r.Changes)
	}
	for _, op := range f.Ops() {
		if op == "set" {
			t.Fatal("no-op set must not call the provider")
		}
	}
}

func TestSetRecordsTTLChangeIsAnUpdate(t *testing.T) {
	f := apexZone()
	in := contract.Record{Name: "@", Type: "TXT", TTL: 60, Data: "site-verification=abc"}
	r := ok(t)(newOps(f).SetRecords(context.Background(), []contract.Record{in}, "", nil, false))
	if len(r.Changes.Add) != 1 || len(r.Changes.Remove) != 1 || r.Changes.Remove[0].TTL != 300 {
		t.Fatalf("%+v", r.Changes)
	}
}

func TestDeleteIsExactAndPassesProviderRecords(t *testing.T) {
	ctx := context.Background()
	f := fakedns.New(zone)
	f.Seed(txt("_acme-challenge", "token-1"), txt("_acme-challenge", "token-2"))
	o := newOps(f)

	// Different data: nothing is deleted, and that is not an error.
	r := ok(t)(o.DeleteRecords(ctx, []contract.Record{rec("_acme-challenge", "TXT", "nope")}, false))
	if len(r.Changes.Remove) != 0 {
		t.Fatalf("%+v", r.Changes)
	}
	// Wrong TTL: nothing.
	r = ok(t)(o.DeleteRecords(ctx, []contract.Record{{Name: "_acme-challenge", Type: "TXT", TTL: 5, Data: "token-1"}}, false))
	if len(r.Changes.Remove) != 0 {
		t.Fatalf("%+v", r.Changes)
	}
	// Exact: only token-1 goes, and the provider is handed its own record.
	ok(t)(o.DeleteRecords(ctx, []contract.Record{rec("_acme-challenge", "TXT", "token-1")}, false))
	var del fakedns.Call
	for _, c := range f.Calls {
		if c.Op == "delete" {
			del = c
		}
	}
	if del.Op != "delete" || len(del.Records) != 1 || del.Records[0].(libdns.TXT).ProviderData == nil {
		t.Fatalf("delete should pass the provider's own record: %+v", del)
	}
	if got := dataOf(ok(t)(o.GetRecords(ctx, nil)).Records); len(got) != 1 || !strings.HasSuffix(got[0], "token-2") {
		t.Fatalf("got %v", got)
	}
}

func TestDeleteWithoutTypeAndDataTakesAllAtNameButNotAtApex(t *testing.T) {
	ctx := context.Background()
	f := apexZone()
	f.Seed(txt("junk", "a"), libdns.Address{Name: "junk", IP: netip.MustParseAddr("192.0.2.5")})
	o := newOps(f)

	r := ok(t)(o.DeleteRecords(ctx, []contract.Record{{Name: "junk"}}, false))
	if len(r.Changes.Remove) != 2 {
		t.Fatalf("%+v", r.Changes)
	}
	_, err := o.DeleteRecords(ctx, []contract.Record{{Name: "@"}}, false)
	wantCode(t, err, contract.CodeForbidden)
}

func TestApexNSAndSOAAreNeverTouched(t *testing.T) {
	ctx := context.Background()
	o := newOps(apexZone())
	_, err := o.AppendRecords(ctx, []contract.Record{rec("@", "NS", "ns9.example.net.")}, false)
	wantCode(t, err, contract.CodeForbidden)
	_, err = o.SetRecords(ctx, []contract.Record{rec("@", "SOA", "x y 1 2 3 4 5")}, "", nil, false)
	wantCode(t, err, contract.CodeForbidden)
	_, err = o.DeleteRecords(ctx, []contract.Record{rec("@", "NS", "ns1.example.net.")}, false)
	wantCode(t, err, contract.CodeForbidden)
	// Delegating a subdomain is fine.
	if _, err := o.AppendRecords(ctx, []contract.Record{rec("sub", "NS", "ns.other.net.")}, false); err != nil {
		t.Fatal(err)
	}
}

func TestSRVRoundTrip(t *testing.T) {
	ctx := context.Background()
	o := newOps(fakedns.New(zone))
	ok(t)(o.AppendRecords(ctx, []contract.Record{rec("_sip._tcp", "SRV", "10 60 5060 sip.example.com.")}, false))
	got := ok(t)(o.GetRecords(ctx, &contract.Filter{Type: "SRV"})).Records
	if len(got) != 1 || got[0].Name != "_sip._tcp" || got[0].Data != "10 60 5060 sip.example.com." {
		t.Fatalf("%+v", got)
	}
}

func TestMissingInterfacesGiveUnsupported(t *testing.T) {
	ctx := context.Background()
	f := fakedns.New(zone)
	ro := &Ops{Provider: fakedns.ReadOnly{F: f}, Zone: zone}
	_, err := ro.AppendRecords(ctx, []contract.Record{rec("a", "TXT", "x")}, false)
	wantCode(t, err, contract.CodeUnsupported)
	ao := &Ops{Provider: fakedns.AppendOnly{F: f}, Zone: zone}
	_, err = ao.SetRecords(ctx, []contract.Record{rec("a", "TXT", "x")}, "", nil, false)
	wantCode(t, err, contract.CodeUnsupported)
	_, err = ao.DeleteRecords(ctx, []contract.Record{rec("a", "TXT", "x")}, false)
	wantCode(t, err, contract.CodeUnsupported)

	if c := Capabilities(fakedns.ReadOnly{F: f}); !c.GetRecords || c.AppendRecords || c.SetRecords || c.DeleteRecords || c.ListZones {
		t.Fatalf("%+v", c)
	}
	if c := Capabilities(f); !(c.GetRecords && c.AppendRecords && c.SetRecords && c.DeleteRecords && c.ListZones) {
		t.Fatalf("%+v", c)
	}
}

func TestValidate(t *testing.T) {
	ctx := context.Background()

	t.Run("zone listed", func(t *testing.T) {
		r := ok(t)(newOps(fakedns.New("example.com.")).Validate(ctx, false))
		if r.Validation.Method != "list-zones" || r.Validation.WriteTest != "skipped" || !r.Capabilities.ListZones {
			t.Fatalf("%+v", r.Validation)
		}
	})
	t.Run("zone not in list", func(t *testing.T) {
		_, err := newOps(fakedns.New("other.org.")).Validate(ctx, false)
		wantCode(t, err, contract.CodeZoneNotFound)
	})
	t.Run("no ZoneLister falls back to reading the zone", func(t *testing.T) {
		o := &Ops{Provider: fakedns.ReadOnly{F: fakedns.New()}, Zone: zone}
		r := ok(t)(o.Validate(ctx, false))
		if r.Validation.Method != "get-records" {
			t.Fatalf("%+v", r.Validation)
		}
	})
	t.Run("write test leaves nothing behind", func(t *testing.T) {
		f := fakedns.New(zone)
		r := ok(t)(newOps(f).Validate(ctx, true))
		if r.Validation.WriteTest != "passed" {
			t.Fatalf("%+v", r.Validation)
		}
		if got := ok(t)(newOps(f).GetRecords(ctx, nil)).Records; len(got) != 0 {
			t.Fatalf("probe record left behind: %v", dataOf(got))
		}
	})
	t.Run("write test needs write support", func(t *testing.T) {
		o := &Ops{Provider: fakedns.ReadOnly{F: fakedns.New()}, Zone: zone}
		_, err := o.Validate(ctx, true)
		wantCode(t, err, contract.CodeUnsupported)
	})
}

func TestProviderErrorsNeverEchoCredentials(t *testing.T) {
	f := fakedns.New(zone)
	f.Fail = errors.New(`GET https://api.example.net/zones?token=s3cr3t-token-value failed: 500 boom`)
	o := &Ops{Provider: f, Zone: zone, Secrets: []string{"s3cr3t-token-value"}}
	_, err := o.GetRecords(context.Background(), nil)
	wantCode(t, err, contract.CodeProviderError)
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("credential leaked: %v", err)
	}
}

func TestProviderErrorClassification(t *testing.T) {
	cases := map[string]string{
		"HTTP 403 Forbidden":                    contract.CodeAuthFailed,
		"unauthorized":                          contract.CodeAuthFailed,
		"dial tcp 10.0.0.4011: connection lost": contract.CodeProviderError,
	}
	for msg, want := range cases {
		if got := ProviderError(errors.New(msg), nil); got.Code != want {
			t.Errorf("%q: got %s, want %s", msg, got.Code, want)
		}
	}
	if got := ProviderError(context.DeadlineExceeded, nil); got.Code != contract.CodeTimeout {
		t.Errorf("got %s", got.Code)
	}
}

func TestSilentDeleteFailureIsDetected(t *testing.T) {
	ctx := context.Background()
	f := fakedns.New(zone)
	f.Seed(txt("x", "one"))
	f.IgnoreDeletes = true
	o := newOps(f)

	_, err := o.DeleteRecords(ctx, []contract.Record{rec("x", "TXT", "one")}, false)
	wantCode(t, err, contract.CodeProviderError)
	if !strings.Contains(err.Error(), "still in the zone") {
		t.Fatal(err)
	}

	// A set-records whose delete step does nothing must not go on to append:
	// that would leave the old and the new value side by side.
	_, err = o.SetRecords(ctx, []contract.Record{rec("x", "TXT", "two")}, contract.ModeRRset, nil, false)
	wantCode(t, err, contract.CodeProviderError)
	for _, op := range f.Ops() {
		if op == "append" {
			t.Fatalf("appended after a failed delete: %v", f.Ops())
		}
	}
}

func TestIdenticalRecordsFromAZoneTransferAreListedOnce(t *testing.T) {
	f := fakedns.New(zone)
	f.Seed(libdns.RR{Name: "@", TTL: 300 * time.Second, Type: "SOA", Data: "ns1.example.com. h.example.com. 1 2 3 4 5"},
		libdns.RR{Name: "@", TTL: 300 * time.Second, Type: "SOA", Data: "ns1.example.com. h.example.com. 1 2 3 4 5"})
	if got := ok(t)(newOps(f).GetRecords(context.Background(), nil)).Records; len(got) != 1 {
		t.Fatalf("want the SOA once, got %v", dataOf(got))
	}
}

func TestHTTPSAndSVCBCompareWithoutParameterQuotes(t *testing.T) {
	for _, c := range []struct {
		typ, a, b string
		same      bool
	}{
		{"HTTPS", `1 . alpn="h2,h3"`, "1 . alpn=h2,h3", true},
		{"SVCB", "1 Svc.Example.com. port=8443", "1 svc.example.com port=8443", true},
		{"HTTPS", "1 . alpn=h2", "1 . alpn=h3", false},
	} {
		if got := normData(c.typ, c.a) == normData(c.typ, c.b); got != c.same {
			t.Errorf("%s %q %q: %v", c.typ, c.a, c.b, got)
		}
	}
}
