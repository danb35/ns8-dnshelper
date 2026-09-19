package registry

import (
	"context"
	"strings"

	"github.com/libdns/cloudflare"
	"github.com/libdns/godaddy"
	"github.com/libdns/hetzner/v2"
	"github.com/libdns/libdns"
	"github.com/libdns/namedotcom"
	"github.com/libdns/rfc2136"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

func init() {
	Register(Def{
		Name:  "cloudflare",
		Label: "Cloudflare",
		Fields: []contract.Field{
			{Name: "api_token", Label: "API token (Zone:DNS:Edit)", Secret: true, Required: true},
			{Name: "zone_token", Label: "Zone:Read token, if api_token is scoped to a single zone", Secret: true},
		},
		Types:        []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes:        "HTTPS/SVCB records are not supported by the provider package. TXT values containing a double quote or backslash are refused: the provider package does not escape them, so they do not round-trip.",
		TXTForbidden: "\"\\",
		New: func(c map[string]string) any {
			return cloudflareProvider{&cloudflare.Provider{APIToken: c["api_token"], ZoneToken: c["zone_token"]}}
		},
	})
	Register(Def{
		Name:  "godaddy",
		Label: "GoDaddy",
		Fields: []contract.Field{
			{Name: "api_key", Label: "API key", Secret: true, Required: true},
			{Name: "api_secret", Label: "API secret", Secret: true, Required: true},
		},
		Types: []string{"A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes: "Uses the production GoDaddy API. GoDaddy only enables its DNS API for accounts that meet its own requirements.",
		New: func(c map[string]string) any {
			return &godaddy.Provider{APIToken: c["api_key"] + ":" + c["api_secret"]}
		},
	})
	Register(Def{
		Name:  "namedotcom",
		Label: "name.com",
		Fields: []contract.Field{
			{Name: "user", Label: "User name", Required: true},
			{Name: "api_token", Label: "API token", Secret: true, Required: true},
		},
		Types: []string{"A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes: "Uses the production name.com API (api.name.com).",
		New: func(c map[string]string) any {
			return &namedotcom.Provider{User: c["user"], Token: c["api_token"], Server: "https://api.name.com"}
		},
	})
	Register(Def{
		Name:  "hetzner",
		Label: "Hetzner",
		Fields: []contract.Field{
			{Name: "api_token", Label: "Hetzner Cloud API token (read & write)", Secret: true, Required: true},
		},
		Types: []string{"A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes: "Uses the Hetzner Cloud DNS API (zones in the Hetzner Console). The old DNS Console API at dns.hetzner.com has been retired.",
		New: func(c map[string]string) any {
			return hetznerProvider{&hetzner.Provider{APIToken: c["api_token"]}}
		},
	})
	Register(Def{
		Name:  "rfc2136",
		Label: "RFC 2136 dynamic update (BIND, Knot, PowerDNS...)",
		Fields: []contract.Field{
			{Name: "server", Label: "Server address, host:port", Required: true},
			{Name: "key_name", Label: "TSIG key name", Required: true},
			{Name: "key_alg", Label: "TSIG algorithm", Required: true, Default: "hmac-sha256"},
			{Name: "key", Label: "TSIG key (base64)", Secret: true, Required: true},
		},
		Types:        []string{"A", "AAAA", "CAA", "CNAME", "HTTPS", "MX", "NS", "SRV", "SVCB", "TXT"},
		Notes:        "Reading a zone needs zone transfer (AXFR) to be allowed for the key. TXT values containing a double quote or backslash are refused: the provider package stores them escaped, so they do not round-trip.",
		TXTForbidden: "\"\\",
		New: func(c map[string]string) any {
			return &rfc2136.Provider{Server: c["server"], KeyName: c["key_name"], KeyAlg: c["key_alg"], Key: c["key"]}
		},
	})
}

// cloudflareProvider works around a quirk of the Cloudflare provider package
// (v0.2.2, verified against the live API): a TXT value longer than 255 bytes is
// read back as `<chunk>" "<chunk>` with the outer quotes stripped, but
// DeleteRecords only matches it when the outer quotes are present, and
// silently deletes nothing otherwise. Every other method is promoted unchanged,
// so the optional libdns interfaces are still detected.
type cloudflareProvider struct{ *cloudflare.Provider }

func (c cloudflareProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	fixed := make([]libdns.Record, len(recs))
	for i, r := range recs {
		fixed[i] = r
		if t, ok := r.(libdns.TXT); ok && strings.Contains(t.Text, `" "`) {
			t.Text = `"` + t.Text + `"`
			fixed[i] = t
		}
	}
	return c.Provider.DeleteRecords(ctx, zone, fixed)
}
