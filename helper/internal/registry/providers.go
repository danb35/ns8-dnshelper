package registry

// Zero-value SRV/MX field audit (2026-09-23), triggered by a live failure
// creating ns8-automx's _autodiscover._tcp SRV 0 0 443 <target> record
// through Cloudflare (see internal/vendored/cloudflare's file-level
// comment): every provider that can write SRV was checked for the same
// mistake -- a numeric field serialized with `omitempty` that is legitimately
// 0 for a real record (SRV priority/weight is commonly 0), so encoding/json
// silently drops it and the provider's API then rejects the request as
// missing that field.
//
//   - cloudflare: BUGGY, confirmed live. Patched locally, see
//     internal/vendored/cloudflare.
//   - namedotcom: BUGGY by the same code pattern (a plain int32 Priority
//     field with omitempty), found by this audit but not confirmed against
//     the live API. Patched locally the same way, see
//     internal/vendored/namedotcom, out of caution.
//   - godaddy.go (this package): safe. gdRecord.Priority/Weight/Port are
//     already *int, so an explicit 0 round-trips through omitempty
//     correctly (a nil pointer, not a zero int, is what omitempty drops).
//   - corenetworks.go (this package): safe, but for a different reason --
//     Core-Networks' add-record API (POST /dnszones/%ZONE%/records/,
//     confirmed against its docs at beta.api.core-networks.de/doc/) has no
//     structured priority/weight/port fields at all, just one opaque "data"
//     string holding the whole zone-file-style RDATA ("0 0 443 target."),
//     so there's nothing for omitempty to drop.
//   - hetzner (github.com/libdns/hetzner/v2 v2.0.1): safe, same reasoning as
//     Core-Networks -- fromRecord() in that package sends the whole RDATA
//     as one opaque hcloud.ZoneRRSetRecord.Value string, no separate
//     priority/weight/port fields.
//   - rfc2136 (github.com/libdns/rfc2136 v1.0.1): safe, empirically -- this
//     is the DNS UPDATE wire protocol, not JSON, so omitempty doesn't apply;
//     also the one provider a real _autodiscover._tcp SRV 0 0 443 <target>
//     record has actually been created through successfully, repeatedly,
//     against live BIND instances during ns8-automx's real-node testing.
//
// Tracked in https://github.com/danb35/ns8-dnshelper/issues/19.

import (
	"context"
	"strings"

	"github.com/libdns/hetzner/v2"
	"github.com/libdns/libdns"
	"github.com/libdns/rfc2136"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
	// Locally vendored, patched copies -- see each package's file-level
	// comment for why. Not github.com/libdns/cloudflare and
	// github.com/libdns/namedotcom directly; go back to those once the
	// zero-value-omitempty bug is fixed upstream.
	"github.com/danb35/ns8-dnshelper/helper/internal/vendored/cloudflare"
	"github.com/danb35/ns8-dnshelper/helper/internal/vendored/namedotcom"
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
		Name:  "corenetworks",
		Label: "Core-Networks",
		Fields: []contract.Field{
			{Name: "login", Label: "API account login (made under API user accounts in the Core-Networks web interface)", Required: true},
			{Name: "password", Label: "API account password", Secret: true, Required: true},
		},
		Types: []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes: "Uses the Core-Networks DNS API at beta.api.core-networks.de with an API account, not the account used for the web interface. Changes are committed to the name servers after every change. The service refuses a TTL below 60 seconds (a shorter one is raised to 60) and uses 1800 when none is given. Slave zones are not listed.",
		New: func(c map[string]string) any {
			return &coreNetworksProvider{Login: c["login"], Password: c["password"]}
		},
		NewCached: func(c map[string]string, cacheDir string) any {
			return &coreNetworksProvider{Login: c["login"], Password: c["password"], cacheDir: cacheDir}
		},
	})
	Register(Def{
		Name:  "godaddy",
		Label: "GoDaddy",
		Fields: []contract.Field{
			{Name: "api_token", Label: "Personal access token (create one at developer.godaddy.com, with domain and DNS scopes)", Secret: true},
			{Name: "api_key", Label: "Legacy API key (classic key, deprecated by GoDaddy; use instead of a token)", Secret: true},
			{Name: "api_secret", Label: "Legacy API secret (classic key, deprecated by GoDaddy)", Secret: true},
		},
		Verify: func(c map[string]string) string {
			switch {
			case c["api_token"] != "" && (c["api_key"] != "" || c["api_secret"] != ""):
				return "give either api_token or api_key and api_secret, not both"
			case c["api_token"] == "" && (c["api_key"] == "" || c["api_secret"] == ""):
				return "missing credential fields: api_token (or api_key and api_secret)"
			}
			return ""
		},
		Types: []string{"A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes: "Uses the production GoDaddy API with a personal access token (the legacy classic API key and secret still work but GoDaddy is deprecating them). GoDaddy does not accept a TTL under 600 seconds: records written with a shorter or no TTL get 600.",
		New: func(c map[string]string) any {
			return &goDaddyProvider{APIToken: c["api_token"], APIKey: c["api_key"], APISecret: c["api_secret"]}
		},
	})
	Register(Def{
		Name:  "namedotcom",
		Label: "name.com",
		Fields: []contract.Field{
			{Name: "user", Label: "User name", Required: true},
			{Name: "api_token", Label: "API token", Secret: true, Required: true},
		},
		Types:        []string{"A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes:        "Uses the production name.com API (api.name.com). name.com does not accept a TTL under 300 seconds: records written with a shorter or no TTL get 300. TXT values containing a double quote or backslash are refused: name.com reads the value as zone-file text, so they do not round-trip.",
		TXTForbidden: "\"\\",
		New: func(c map[string]string) any {
			return nameComProvider{&namedotcom.Provider{User: c["user"], Token: c["api_token"], Server: "https://api.name.com"}}
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
