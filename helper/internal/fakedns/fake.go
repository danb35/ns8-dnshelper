// Package fakedns is an in-memory libdns provider for tests. It follows the
// documented libdns semantics (RRset replacement in SetRecords, exact-match
// deletion with empty fields as wildcards) and, like real provider packages,
// splits long TXT values into 255-byte strings internally.
package fakedns

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Call is one provider call, for assertions.
type Call struct {
	Op      string
	Zone    string
	Records []libdns.Record
}

type stored struct {
	id   int
	name string
	ttl  time.Duration
	typ  string
	data []string // TXT chunks; a single element for every other type
}

// Fake is a provider implementing every optional libdns interface.
type Fake struct {
	mu     sync.Mutex
	nextID int
	recs   []stored

	Zones   []string         // returned by ListZones
	Fail    error            // when set, every call fails with it
	FailOps map[string]error // per-operation failures: "get", "append", "set", "delete"
	// QuoteChunks makes reads return long TXT values the way Cloudflare's
	// provider does: the 255-byte strings joined by `" "`.
	QuoteChunks bool
	// IgnoreDeletes makes DeleteRecords report success without deleting.
	IgnoreDeletes bool
	Calls         []Call
}

// New returns a Fake serving the given zones.
func New(zones ...string) *Fake { return &Fake{Zones: zones, nextID: 1} }

// Seed adds records without recording a call.
func (f *Fake) Seed(recs ...libdns.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range recs {
		f.add(r.RR())
	}
}

// Ops returns the recorded call names, in order.
func (f *Fake) Ops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.Calls {
		out = append(out, c.Op)
	}
	return out
}

func chunk(s string) []string {
	if len(s) <= 255 {
		return []string{s}
	}
	var out []string
	for len(s) > 255 {
		out = append(out, s[:255])
		s = s[255:]
	}
	return append(out, s)
}

func (f *Fake) add(rr libdns.RR) stored {
	s := stored{id: f.nextID, name: rr.Name, ttl: rr.TTL, typ: rr.Type, data: []string{rr.Data}}
	if rr.Type == "TXT" {
		s.data = chunk(rr.Data)
	}
	f.nextID++
	f.recs = append(f.recs, s)
	return s
}

// typed builds the typed libdns record for a stored entry, carrying the
// stored id as ProviderData the way real providers carry their record IDs.
func (f *Fake) typed(s stored) libdns.Record {
	sep := ""
	if f.QuoteChunks {
		sep = `" "`
	}
	rr := libdns.RR{Name: s.name, TTL: s.ttl, Type: s.typ, Data: strings.Join(s.data, sep)}
	rec, err := rr.Parse()
	if err != nil {
		return rr
	}
	switch r := rec.(type) {
	case libdns.TXT:
		r.ProviderData = s.id
		return r
	case libdns.CNAME:
		r.ProviderData = s.id
		return r
	case libdns.Address:
		r.ProviderData = s.id
		return r
	case libdns.SRV:
		r.ProviderData = s.id
		return r
	case libdns.MX:
		r.ProviderData = s.id
		return r
	}
	return rec
}

func (f *Fake) begin(op, zone string, recs []libdns.Record) error {
	f.Calls = append(f.Calls, Call{Op: op, Zone: zone, Records: recs})
	if err := f.FailOps[op]; err != nil {
		return err
	}
	return f.Fail
}

func (f *Fake) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("get", zone, nil); err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(f.recs))
	for _, s := range f.recs {
		out = append(out, f.typed(s))
	}
	return out, nil
}

func (f *Fake) AppendRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("append", zone, recs); err != nil {
		return nil, err
	}
	var out []libdns.Record
	for _, r := range recs {
		out = append(out, f.typed(f.add(r.RR())))
	}
	return out, nil
}

func (f *Fake) SetRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("set", zone, recs); err != nil {
		return nil, err
	}
	touched := map[string]bool{}
	for _, r := range recs {
		rr := r.RR()
		touched[rr.Name+"|"+rr.Type] = true
	}
	kept := f.recs[:0:0]
	for _, s := range f.recs {
		if !touched[s.name+"|"+s.typ] {
			kept = append(kept, s)
		}
	}
	f.recs = kept
	var out []libdns.Record
	for _, r := range recs {
		out = append(out, f.typed(f.add(r.RR())))
	}
	return out, nil
}

func (f *Fake) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("delete", zone, recs); err != nil {
		return nil, err
	}
	if f.IgnoreDeletes {
		return nil, nil
	}
	var out []libdns.Record
	for _, r := range recs {
		rr := r.RR()
		kept := f.recs[:0:0]
		for _, s := range f.recs {
			match := s.name == rr.Name &&
				(rr.Type == "" || s.typ == rr.Type) &&
				(rr.TTL == 0 || s.ttl == rr.TTL) &&
				(rr.Data == "" || strings.Join(s.data, "") == rr.Data || strings.Join(s.data, `" "`) == rr.Data)
			if match {
				out = append(out, f.typed(s))
			} else {
				kept = append(kept, s)
			}
		}
		f.recs = kept
	}
	return out, nil
}

func (f *Fake) ListZones(context.Context) ([]libdns.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("list-zones", "", nil); err != nil {
		return nil, err
	}
	out := make([]libdns.Zone, 0, len(f.Zones))
	for _, z := range f.Zones {
		out = append(out, libdns.Zone{Name: z})
	}
	return out, nil
}

// Chunks returns how many strings the stored TXT values at name are split into.
func (f *Fake) Chunks(name string) []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []int
	for _, s := range f.recs {
		if s.name == name && s.typ == "TXT" {
			out = append(out, len(s.data))
		}
	}
	return out
}

// ReadOnly exposes only GetRecords.
type ReadOnly struct{ F *Fake }

func (r ReadOnly) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return r.F.GetRecords(ctx, zone)
}

// AppendOnly exposes GetRecords and AppendRecords.
type AppendOnly struct{ F *Fake }

func (r AppendOnly) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return r.F.GetRecords(ctx, zone)
}

func (r AppendOnly) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return r.F.AppendRecords(ctx, zone, recs)
}

// SetOnly exposes GetRecords and SetRecords.
type SetOnly struct{ F *Fake }

func (r SetOnly) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return r.F.GetRecords(ctx, zone)
}

func (r SetOnly) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return r.F.SetRecords(ctx, zone, recs)
}
