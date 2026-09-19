// Package dnsops implements the dnshelper operations on top of the optional
// libdns interfaces. It knows nothing about specific providers.
package dnsops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// Capabilities reports which optional libdns interfaces a provider implements.
func Capabilities(p any) contract.Capabilities {
	_, get := p.(libdns.RecordGetter)
	_, app := p.(libdns.RecordAppender)
	_, set := p.(libdns.RecordSetter)
	_, del := p.(libdns.RecordDeleter)
	_, zl := p.(libdns.ZoneLister)
	return contract.Capabilities{GetRecords: get, AppendRecords: app, SetRecords: set, DeleteRecords: del, ListZones: zl}
}

// Ops runs operations against one provider instance and one zone.
type Ops struct {
	Provider any
	Zone     string   // as given by the caller, with or without trailing dot
	Secrets  []string // credential values, scrubbed from provider error text
}

type entry struct {
	c contract.Record
	l libdns.Record // as returned by the provider, ProviderData intact
}

func unsupported(what string) *contract.Error {
	return &contract.Error{Code: contract.CodeUnsupported, Message: "the provider package does not support " + what}
}

// read returns the zone's current records.
func (o *Ops) read(ctx context.Context) ([]entry, error) {
	g, ok := o.Provider.(libdns.RecordGetter)
	if !ok {
		return nil, unsupported("reading records")
	}
	recs, err := g.GetRecords(ctx, ZoneFQDN(o.Zone))
	if err != nil {
		return nil, ProviderError(err, o.Secrets)
	}
	z := zoneBare(o.Zone)
	out := make([]entry, 0, len(recs))
	for _, r := range recs {
		c := fromLibdns(r)
		if lc := strings.ToLower(c.Name); lc == z || strings.HasSuffix(lc, "."+z) {
			c.Name = libdns.RelativeName(lc, z)
		}
		// A zone transfer lists the SOA at both ends; drop exact repeats.
		dup := false
		for _, e := range out {
			if e.c == c {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, entry{c: c, l: r})
		}
	}
	return out, nil
}

func plain(es []entry) []contract.Record {
	out := make([]contract.Record, len(es))
	for i, e := range es {
		out[i] = e.c
	}
	return out
}

func lookup(es []entry, r contract.Record) (entry, bool) {
	for _, e := range es {
		if same(e.c, r) {
			return e, true
		}
	}
	return entry{}, false
}

// libFor builds the provider records for recs, reusing the provider's own
// record (with its ProviderData) whenever recs already exist.
func libFor(existing []entry, recs []contract.Record) ([]libdns.Record, error) {
	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		if e, ok := lookup(existing, r); ok {
			out = append(out, e.l)
			continue
		}
		l, err := toLibdns(r)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

func nonNil(r []contract.Record) []contract.Record {
	if r == nil {
		return []contract.Record{}
	}
	return r
}

func fromLibdnsAll(rs []libdns.Record) []contract.Record {
	out := make([]contract.Record, 0, len(rs))
	for _, r := range rs {
		out = append(out, fromLibdns(r))
	}
	return out
}

func changes(p Plan) *contract.Changes {
	return &contract.Changes{Add: nonNil(p.Add), Remove: nonNil(p.Remove)}
}

// GetRecords lists the zone's records, optionally filtered.
func (o *Ops) GetRecords(ctx context.Context, f *contract.Filter) (contract.Response, error) {
	es, err := o.read(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	var out []contract.Record
	for _, e := range es {
		if f != nil && f.Name != "" && e.c.Name != normName(f.Name) {
			continue
		}
		if f != nil && f.Type != "" && e.c.Type != strings.ToUpper(f.Type) {
			continue
		}
		out = append(out, e.c)
	}
	return contract.Response{OK: true, Records: nonNil(out)}, nil
}

// AppendRecords adds records that are not already present.
func (o *Ops) AppendRecords(ctx context.Context, input []contract.Record, dryRun bool) (contract.Response, error) {
	app, ok := o.Provider.(libdns.RecordAppender)
	if !ok {
		return contract.Response{}, unsupported("appending records")
	}
	in, err := NormalizeAll(o.Zone, input)
	if err != nil {
		return contract.Response{}, err
	}
	es, err := o.read(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	plan, err := PlanAppend(plain(es), in)
	if err != nil {
		return contract.Response{}, err
	}
	if err := CheckAfter(o.Zone, plan); err != nil {
		return contract.Response{}, err
	}
	resp := contract.Response{OK: true, DryRun: dryRun, Records: []contract.Record{}, Changes: changes(plan)}
	if dryRun || len(plan.Add) == 0 {
		return resp, nil
	}
	libs, err := libFor(nil, plan.Add)
	if err != nil {
		return contract.Response{}, err
	}
	done, err := app.AppendRecords(ctx, ZoneFQDN(o.Zone), libs)
	if err != nil {
		return contract.Response{}, ProviderError(err, o.Secrets)
	}
	resp.Records = fromLibdnsAll(done)
	return resp, nil
}

// SetRecords replaces or merges RRsets. See contract.ModeMerge and ModeRRset.
//
// The change is computed here and applied as DeleteRecords + AppendRecords
// rather than SetRecords: provider packages do not agree on what SetRecords
// does (Cloudflare's updates one record per input by name and type, and fails
// when the RRset has several members). SetRecords is used only for providers
// that cannot delete or append.
func (o *Ops) SetRecords(ctx context.Context, input []contract.Record, mode string, replacePrefixes []string, dryRun bool) (contract.Response, error) {
	app, canApp := o.Provider.(libdns.RecordAppender)
	del, canDel := o.Provider.(libdns.RecordDeleter)
	set, canSet := o.Provider.(libdns.RecordSetter)
	if !(canApp && canDel) && !canSet {
		return contract.Response{}, unsupported("setting records")
	}
	in, err := NormalizeAll(o.Zone, input)
	if err != nil {
		return contract.Response{}, err
	}
	es, err := o.read(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	plan, err := PlanSet(plain(es), in, mode, replacePrefixes)
	if err != nil {
		return contract.Response{}, err
	}
	if err := CheckAfter(o.Zone, plan); err != nil {
		return contract.Response{}, err
	}
	resp := contract.Response{OK: true, DryRun: dryRun, Records: []contract.Record{}, Changes: changes(plan)}
	if dryRun || plan.Empty() {
		return resp, nil
	}

	if !(canApp && canDel) {
		libs, err := libFor(es, plan.Desired)
		if err != nil {
			return contract.Response{}, err
		}
		done, err := set.SetRecords(ctx, ZoneFQDN(o.Zone), libs)
		if err != nil {
			return contract.Response{}, ProviderError(err, o.Secrets)
		}
		resp.Records = fromLibdnsAll(done)
		return resp, nil
	}

	zone := ZoneFQDN(o.Zone)
	if len(plan.Remove) > 0 {
		var old []libdns.Record
		for _, r := range plan.Remove {
			if e, ok := lookup(es, r); ok {
				old = append(old, e.l)
			}
		}
		if _, err := del.DeleteRecords(ctx, zone, old); err != nil {
			return contract.Response{}, ProviderError(err, o.Secrets)
		}
		if err := o.verifyRemoved(ctx, plan.Remove); err != nil {
			// Nothing has been added yet. Put back whatever did get removed.
			return contract.Response{}, o.restoreMissing(ctx, app, plan.Remove, err)
		}
	}
	if len(plan.Add) > 0 {
		libs, err := libFor(nil, plan.Add)
		if err == nil {
			var done []libdns.Record
			if done, err = app.AppendRecords(ctx, zone, libs); err == nil {
				resp.Records = fromLibdnsAll(done)
				return resp, nil
			}
			err = ProviderError(err, o.Secrets)
		}
		return contract.Response{}, o.restore(ctx, app, plan.Remove, err)
	}
	return resp, nil
}

// verifyRemoved re-reads the zone and fails if any of removed is still there.
// Providers differ in what DeleteRecords returns, and some delete nothing yet
// report success when their matching does not fit the record, so the zone
// itself is the only reliable witness.
func (o *Ops) verifyRemoved(ctx context.Context, removed []contract.Record) error {
	es, err := o.read(ctx)
	if err != nil {
		return err
	}
	left := 0
	for _, r := range removed {
		if contains(plain(es), r) {
			left++
		}
	}
	if left > 0 {
		return &contract.Error{Code: contract.CodeProviderError,
			Message: fmt.Sprintf("the provider reported success but %d record(s) that should have been deleted are still in the zone", left)}
	}
	return nil
}

// restoreMissing re-adds those of removed that are no longer in the zone.
func (o *Ops) restoreMissing(ctx context.Context, app libdns.RecordAppender, removed []contract.Record, cause error) error {
	es, err := o.read(context.WithoutCancel(ctx))
	if err != nil {
		return cause
	}
	var gone []contract.Record
	for _, r := range removed {
		if !contains(plain(es), r) {
			gone = append(gone, r)
		}
	}
	return o.restore(ctx, app, gone, cause)
}

// restore puts back records removed by a set-records whose append step failed,
// and returns the error to report.
func (o *Ops) restore(ctx context.Context, app libdns.RecordAppender, removed []contract.Record, cause error) error {
	if len(removed) == 0 {
		return cause
	}
	var back []libdns.Record
	for _, r := range removed {
		if l, err := toLibdns(r); err == nil {
			back = append(back, l)
		}
	}
	if _, err := app.AppendRecords(context.WithoutCancel(ctx), ZoneFQDN(o.Zone), back); err != nil {
		return &contract.Error{Code: contract.CodeProviderError,
			Message: "set-records failed halfway and the removed records could not be restored; check the zone"}
	}
	var ce *contract.Error
	if errors.As(cause, &ce) {
		return &contract.Error{Code: ce.Code, Message: ce.Message + " (the zone was left unchanged)"}
	}
	return cause
}

// DeleteRecords removes existing records matching the input. Deleting
// something that is not there is not an error.
func (o *Ops) DeleteRecords(ctx context.Context, input []contract.Record, dryRun bool) (contract.Response, error) {
	del, ok := o.Provider.(libdns.RecordDeleter)
	if !ok {
		return contract.Response{}, unsupported("deleting records")
	}
	in := make([]contract.Record, 0, len(input))
	for _, r := range input {
		n, err := Normalize(o.Zone, r)
		if err != nil {
			return contract.Response{}, err
		}
		in = append(in, n)
	}
	es, err := o.read(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	plan, err := PlanDelete(plain(es), in)
	if err != nil {
		return contract.Response{}, err
	}
	resp := contract.Response{OK: true, DryRun: dryRun, Records: []contract.Record{}, Changes: changes(plan)}
	if dryRun || len(plan.Remove) == 0 {
		return resp, nil
	}
	var libs []libdns.Record
	for _, r := range plan.Remove {
		if e, ok := lookup(es, r); ok {
			libs = append(libs, e.l)
		}
	}
	done, err := del.DeleteRecords(ctx, ZoneFQDN(o.Zone), libs)
	if err != nil {
		return contract.Response{}, ProviderError(err, o.Secrets)
	}
	if err := o.verifyRemoved(ctx, plan.Remove); err != nil {
		return contract.Response{}, err
	}
	resp.Records = fromLibdnsAll(done)
	return resp, nil
}

// ListZones returns the zones the credentials can see, sorted, as bare names.
func (o *Ops) ListZones(ctx context.Context) (contract.Response, error) {
	zl, ok := o.Provider.(libdns.ZoneLister)
	if !ok {
		return contract.Response{}, unsupported("listing zones")
	}
	zones, err := zl.ListZones(ctx)
	if err != nil {
		return contract.Response{}, ProviderError(err, o.Secrets)
	}
	out := make([]string, 0, len(zones))
	for _, z := range zones {
		out = append(out, zoneBare(z.Name))
	}
	sort.Strings(out)
	return contract.Response{OK: true, Records: []contract.Record{}, Zones: out}, nil
}

// Validate checks that the credentials work for the zone. It is read-only
// unless writeTest is set, in which case it also creates and deletes a
// throwaway TXT record.
func (o *Ops) Validate(ctx context.Context, writeTest bool) (contract.Response, error) {
	v := contract.Validation{WriteTest: "skipped"}
	viaList := false
	if zl, ok := o.Provider.(libdns.ZoneLister); ok {
		// A zone-scoped token may be refused the zone list; then fall back
		// to reading the zone itself.
		if zones, err := zl.ListZones(ctx); err == nil {
			viaList = true
			v.Method = "list-zones"
			found := false
			for _, z := range zones {
				if zoneBare(z.Name) == zoneBare(o.Zone) {
					found = true
				}
			}
			if !found {
				return contract.Response{}, &contract.Error{Code: contract.CodeZoneNotFound,
					Message: "the credentials are valid but do not give access to zone " + zoneBare(o.Zone)}
			}
			v.ZoneFound = true
		}
	}
	if !viaList {
		v.Method = "get-records"
		if _, err := o.read(ctx); err != nil {
			return contract.Response{}, err
		}
		v.ZoneFound = true
	}
	if writeTest {
		v.WriteTest = "failed"
		if err := o.writeProbe(ctx); err != nil {
			return contract.Response{}, err
		}
		v.WriteTest = "passed"
	}
	caps := Capabilities(o.Provider)
	return contract.Response{OK: true, Records: []contract.Record{}, Validation: &v, Capabilities: &caps}, nil
}

func (o *Ops) writeProbe(ctx context.Context) error {
	if _, ok := o.Provider.(libdns.RecordAppender); !ok {
		return unsupported("appending records")
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	probe := contract.Record{Name: "_dnshelper-test-" + hex.EncodeToString(b[:]), Type: "TXT", TTL: 300, Data: "dnshelper write test"}
	if _, err := o.AppendRecords(ctx, []contract.Record{probe}, false); err != nil {
		return err
	}
	// Clean up even if the caller's context was cancelled meanwhile. The TTL is
	// left out of the delete: some providers raise a short TTL to their own
	// minimum, and a stated TTL must match exactly.
	probe.TTL = 0
	if _, err := o.DeleteRecords(context.WithoutCancel(ctx), []contract.Record{probe}, false); err != nil {
		return &contract.Error{Code: contract.CodeProviderError,
			Message: "write test record " + probe.Name + " was created but could not be removed; delete it manually"}
	}
	return nil
}

// authRe is a heuristic: provider packages do not export typed errors.
var authRe = regexp.MustCompile(`\b(401|403)\b|unauthori[sz]ed|forbidden|authentication|invalid (api )?token|bad credentials`)

// zoneRe matches the answers providers give for a domain they do not host.
var zoneRe = regexp.MustCompile(`unknown_domain`)

// ProviderError converts an error from a provider package into a structured
// error whose message cannot leak the credentials.
func ProviderError(err error, secrets []string) *contract.Error {
	var ce *contract.Error
	if errors.As(err, &ce) {
		return ce
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &contract.Error{Code: contract.CodeTimeout, Message: "the DNS provider did not answer in time"}
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	if authRe.MatchString(low) {
		return &contract.Error{Code: contract.CodeAuthFailed,
			Message: "the DNS provider rejected the credentials, or they lack permission for this zone"}
	}
	if zoneRe.MatchString(low) {
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "the DNS provider does not host this zone"}
	}
	for _, s := range secrets {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, "***")
		}
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return &contract.Error{Code: contract.CodeProviderError, Message: "provider request failed: " + msg}
}
