package registry

import (
	"context"
	"time"

	"github.com/libdns/libdns"

	// Locally vendored, patched copy -- see providers.go and the package's
	// own file-level comment.
	"github.com/danb35/ns8-dnshelper/helper/internal/vendored/namedotcom"
)

// nameComMinTTL is the lowest TTL the name.com API accepts; a smaller or unset
// TTL is refused with "TTL must be a number greater than or equal to 300".
const nameComMinTTL = 300 * time.Second

// nameComProvider adapts the libdns name.com package (v0.9.0), which sends the
// TTL of a record as given, so a record without a TTL (0, "unspecified" in
// libdns) is rejected. Records written are raised to the API minimum; reads
// and deletes, and every other method (ListZones, ...), pass through.
type nameComProvider struct{ *namedotcom.Provider }

func (n nameComProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return n.Provider.AppendRecords(ctx, zone, withMinTTL(recs))
}

func (n nameComProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return n.Provider.SetRecords(ctx, zone, withMinTTL(recs))
}

// withMinTTL returns recs as generic RRs with TTLs of at least nameComMinTTL.
// The package reads only Record.RR(), and RR data uses the same text form as
// the typed records.
func withMinTTL(recs []libdns.Record) []libdns.Record {
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		rr := r.RR()
		if rr.TTL < nameComMinTTL {
			rr.TTL = nameComMinTTL
		}
		out[i] = rr
	}
	return out
}
