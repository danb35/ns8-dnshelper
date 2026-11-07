// Package app dispatches a contract.Request to the right operation.
package app

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
	"github.com/danb35/ns8-dnshelper/helper/internal/dnsops"
	"github.com/danb35/ns8-dnshelper/helper/internal/psl"
	"github.com/danb35/ns8-dnshelper/helper/internal/registry"
	"github.com/danb35/ns8-dnshelper/helper/internal/zonefile"
	"github.com/danb35/ns8-dnshelper/helper/internal/zonelock"
)

// Options configure a Run.
type Options struct {
	// LockDir holds the per-zone lock files. Empty disables locking.
	LockDir string
	// CacheDir is where a provider may keep a session token between runs. Empty
	// means no caching: every run logs in again.
	CacheDir string
	// Timeout bounds the whole run, lock wait included.
	Timeout time.Duration
}

func fail(err error) contract.Response {
	var ce *contract.Error
	if !errors.As(err, &ce) {
		ce = &contract.Error{Code: contract.CodeProviderError, Message: "internal error"}
	}
	return contract.Response{OK: false, Error: ce, Records: []contract.Record{}}
}

func mutates(req contract.Request) bool {
	switch req.Op {
	case contract.OpAppendRecords, contract.OpSetRecords, contract.OpDeleteRecords, contract.OpApplyChanges:
		return !req.DryRun
	case contract.OpValidate:
		return req.WriteTest
	}
	return false
}

// Run executes req. It never returns credentials in the response.
func Run(ctx context.Context, req contract.Request, opt Options) contract.Response {
	if opt.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opt.Timeout)
		defer cancel()
	}

	if req.Op == contract.OpListProviders {
		resp := contract.Response{OK: true, Records: []contract.Record{}, Providers: []contract.ProviderInfo{}}
		for _, d := range registry.All() {
			resp.Providers = append(resp.Providers, d.Info())
		}
		return resp
	}

	if req.Op == contract.OpRegistrableDomains {
		if len(req.Names) > 5000 {
			return fail(&contract.Error{Code: contract.CodeInvalidRequest, Message: "too many names"})
		}
		return contract.Response{OK: true, Records: []contract.Record{}, Candidates: psl.Candidates(req.Names)}
	}

	// Zone files: reading one, or writing given records (a snapshot), needs
	// no provider.
	if req.Op == contract.OpParseZone || (req.Op == contract.OpExportZone && req.Records != nil) {
		zone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Zone)), ".")
		if !zonelock.ValidZone(zone) {
			return fail(&contract.Error{Code: contract.CodeInvalidRequest, Message: "invalid zone name"})
		}
		if req.Op == contract.OpExportZone {
			return contract.Response{OK: true, Records: []contract.Record{}, Text: zonefile.Export(zone, req.Records)}
		}
		recs, skipped, err := zonefile.Parse(zone, req.Text)
		if err != nil {
			return fail(err)
		}
		return contract.Response{OK: true, Records: recs, Skipped: skipped}
	}

	def, ok := registry.Get(req.Provider)
	if !ok {
		return fail(&contract.Error{Code: contract.CodeUnknownProvider, Message: "unknown provider " + quote(req.Provider)})
	}

	if req.Op == contract.OpCapabilities {
		caps := dnsops.Capabilities(def.New(nil))
		return contract.Response{OK: true, Records: []contract.Record{}, Capabilities: &caps}
	}

	switch req.Op {
	case contract.OpValidate, contract.OpListZones, contract.OpGetRecords, contract.OpAppendRecords, contract.OpSetRecords, contract.OpDeleteRecords, contract.OpApplyChanges, contract.OpDiffRecords, contract.OpExportZone, contract.OpCheckPropagation:
	default:
		return fail(&contract.Error{Code: contract.CodeInvalidRequest, Message: "unknown op " + quote(req.Op)})
	}

	zone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Zone)), ".")
	if req.Op != contract.OpListZones && !zonelock.ValidZone(zone) {
		return fail(&contract.Error{Code: contract.CodeInvalidRequest, Message: "invalid zone name"})
	}
	cred, err := def.Check(req.Credentials)
	if err != nil {
		return fail(err)
	}

	if req.Op == contract.OpAppendRecords || req.Op == contract.OpSetRecords || req.Op == contract.OpApplyChanges {
		written := req.Records
		if req.Op == contract.OpApplyChanges {
			written = req.Add
		}
		for _, r := range written {
			if strings.EqualFold(r.Type, "TXT") && def.TXTForbidden != "" && strings.ContainsAny(r.Data, def.TXTForbidden) {
				return fail(&contract.Error{Code: contract.CodeInvalidRequest, Message: "provider " +
					def.Name + " cannot store TXT values containing " + forbiddenChars(def.TXTForbidden) + " (record " + quote(r.Name) + ")"})
			}
		}
	}

	if opt.LockDir != "" && mutates(req) {
		release, err := zonelock.Acquire(ctx, opt.LockDir, zone)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return fail(&contract.Error{Code: contract.CodeLocked, Message: "another change to this zone is in progress"})
			}
			return fail(&contract.Error{Code: contract.CodeProviderError, Message: "cannot take the zone lock"})
		}
		defer release()
	}

	provider := def.New(cred)
	if opt.CacheDir != "" && def.NewCached != nil {
		provider = def.NewCached(cred, opt.CacheDir)
	}
	o := &dnsops.Ops{Provider: provider, Zone: zone, Secrets: def.Secrets(cred)}
	var resp contract.Response
	switch req.Op {
	case contract.OpValidate:
		resp, err = o.Validate(ctx, req.WriteTest)
	case contract.OpListZones:
		resp, err = o.ListZones(ctx)
	case contract.OpGetRecords:
		resp, err = o.GetRecords(ctx, req.Filter)
	case contract.OpAppendRecords:
		resp, err = o.AppendRecords(ctx, req.Records, req.DryRun)
	case contract.OpSetRecords:
		resp, err = o.SetRecords(ctx, req.Records, req.Mode, req.ReplacePrefixes, req.DryRun)
	case contract.OpDeleteRecords:
		resp, err = o.DeleteRecords(ctx, req.Records, req.DryRun)
	case contract.OpApplyChanges:
		resp, err = o.ApplyChanges(ctx, req.Remove, req.Add, req.DryRun)
	case contract.OpDiffRecords:
		resp, err = o.DiffRecords(ctx, req.Records, req.Mode)
	case contract.OpExportZone:
		resp, err = o.ExportZone(ctx)
	case contract.OpCheckPropagation:
		resp, err = o.CheckPropagation(ctx, req.Filter)
	}
	if err != nil {
		resp = fail(err)
	}
	// What the zone held before a write, also when the write failed: the
	// snapshot is most useful then.
	resp.Before = o.Before
	return resp
}

func quote(s string) string {
	if len(s) > 40 {
		s = s[:40] + "..."
	}
	return `"` + strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s) + `"`
}

// forbiddenChars names the characters of a provider's TXTForbidden list.
func forbiddenChars(set string) string {
	var names []string
	for _, c := range set {
		switch c {
		case '"':
			names = append(names, "a double quote")
		case '\\':
			names = append(names, "a backslash")
		default:
			names = append(names, strconv.Quote(string(c)))
		}
	}
	return strings.Join(names, " or ")
}
