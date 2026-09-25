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
//   - digitalocean.go (this package, added after the audit): safe. Its own
//     client, not github.com/libdns/digitalocean (which never fills the
//     structured fields at all, see the file's comment); priority, weight
//     and port are *int, so an explicit 0 is sent, verified against the live
//     API with a 0 0 443 SRV record.
//   - linode.go (this package, added after the audit): safe. Its own client,
//     not github.com/libdns/linode v0.5.0 (which is zero-safe but reads SRV
//     names doubled, see the file's comment); priority, weight and port are
//     *int, verified against the live API with a 0 0 443 SRV record.
//   - porkbun.go (this package, added after the audit): safe. Its own client,
//     not github.com/libdns/porkbun (which never sends a priority at all); the
//     priority is a string sent whenever the type has one, so "0" is always
//     present, verified live with a 0 0 443 SRV record.
//   - desec.go (this package, added after the audit): safe. Its own client,
//     not github.com/libdns/desec (which misreads long TXT values, see the
//     file's comment); deSEC takes every value as one presentation-format
//     string, so there is no separate field to drop; verified live with a
//     0 0 443 SRV record.
//   - gandi.go (this package, added after the audit): safe. Its own client,
//     not github.com/libdns/gandi (whose SetRecords appends and whose TXT
//     values do not round-trip, see the file's comment); like Core-Networks,
//     LiveDNS takes every value as one presentation-format string ("0 0 443
//     target."), so there is no separate field to drop; verified live with a
//     0 0 443 SRV record.
//   - vultr.go (this package, added after the audit): safe. Its own client,
//     not github.com/libdns/vultr/v2 (whose delete can remove a record of
//     another type, see the file's comment); the priority is a *int sent
//     whenever the type has one, so an explicit 0 is always present, verified
//     live with a 0 0 443 SRV record.
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
//   - route53 (github.com/libdns/route53 v1.6.2, added after the audit): safe,
//     same reasoning as Core-Networks -- every value, SRV included, goes out
//     as one ResourceRecord.Value string; checked live with 0 0 443.
//   - powerdns.go (this package, added after the audit): safe. Its own client,
//     not github.com/libdns/powerdns (built on a pre-release libdns API); the
//     PowerDNS API takes every value as one presentation-format string, so
//     there is no separate field to drop; verified against PowerDNS 4.9 and
//     5.0 in Docker with a 0 0 443 SRV record.
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
		Name:  "digitalocean",
		Label: "DigitalOcean",
		Fields: []contract.Field{
			{Name: "api_token", Label: "Personal access token (custom scopes: domain create, read, update and delete)", Secret: true, Required: true},
		},
		Types:        []string{"A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes:        "A DigitalOcean token cannot be limited to some domains: it can change every domain of the account, so keep the zones in an account (or team) of their own if that matters. DigitalOcean does not accept a TTL under 30 seconds: a shorter one is raised to 30, and a record without a TTL gets the zone's default (1800). TXT values containing a backslash, and A or AAAA names containing an underscore, are refused by DigitalOcean. CAA records are not supported yet.",
		TXTForbidden: "\\",
		New: func(c map[string]string) any {
			return &digitalOceanProvider{APIToken: c["api_token"]}
		},
	})
	Register(Def{
		Name:  "desec",
		Label: "deSEC",
		Fields: []contract.Field{
			{Name: "token", Label: "API token (no permission to create or delete domains needed)", Secret: true, Required: true},
		},
		Types: []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes: "Create a token under Token Management at desec.io; it needs neither \"Can create domains\" nor \"Can delete domains\". Leave \"Maximum unused period\" empty: dnshelper only uses the token when a record changes. If you restrict it to a subnet, include the NethServer node's public address; if you give it RRset policies, they must allow the names dnshelper writes. Each domain has its own minimum TTL: shorter TTLs are raised to it, and a record without a TTL gets 3600. The TTL is shared by all records with the same name and type. deSEC limits changes to 15 a minute and 100 an hour per domain; dnshelper waits up to 90 seconds for the limit, then reports how long to wait.",
		New: func(c map[string]string) any {
			return &desecProvider{Token: c["token"]}
		},
	})
	Register(Def{
		Name:  "gandi",
		Label: "Gandi LiveDNS",
		Fields: []contract.Field{
			{Name: "api_token", Label: "Personal access token with \"Manage domain name technical configurations\"", Secret: true, Required: true},
		},
		Types: []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes: "Create a personal access token in the Gandi Admin application, for the organization that holds the domains, with the permission \"Manage domain name technical configurations\" (Gandi then also ticks \"See and renew domain names\"); it can be limited to some domains. Tokens expire: renew or replace the token before its end date and update the credential. Gandi does not accept a TTL under 300 seconds: shorter ones become 300. The TTL is shared by all records with the same name and type.",
		New: func(c map[string]string) any {
			return &gandiProvider{Token: c["api_token"]}
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
		Name:  "linode",
		Label: "Linode (Akamai)",
		Fields: []contract.Field{
			{Name: "api_token", Label: "Personal access token (Domains: Read/Write, nothing else)", Secret: true, Required: true},
		},
		Types: []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes: "A Linode token reaches every domain of the account unless it is made by a restricted user with grants for only some domains. Linode rounds a TTL up to the next value it allows (30, 120, 300, 3600, 7200, ...); a record without a TTL gets the zone's default. SRV records can only sit directly under the zone (_service._protocol), not under a subdomain. CAA records cannot have flags. Changes can take several minutes to reach Linode's name servers.",
		New: func(c map[string]string) any {
			return &linodeProvider{APIToken: c["api_token"]}
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
		Name:  "route53",
		Label: "Amazon Route 53",
		Fields: []contract.Field{
			{Name: "access_key_id", Label: "Access key ID of an IAM user limited to the hosted zones (see the README for a policy)", Required: true},
			{Name: "secret_access_key", Label: "Secret access key", Secret: true, Required: true},
		},
		Types: []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes: "Give the IAM user route53:ListResourceRecordSets and route53:ChangeResourceRecordSets on the hosted zones only, plus route53:ListHostedZonesByName (to find a zone) and route53:ListHostedZones (for the zone list), which AWS cannot limit to some zones; the README has the policy. Private hosted zones are not listed.",
		New: func(c map[string]string) any {
			return newRoute53(c["access_key_id"], c["secret_access_key"])
		},
	})
	Register(Def{
		Name:  "porkbun",
		Label: "Porkbun",
		Fields: []contract.Field{
			{Name: "api_key", Label: "API key (pk1_...)", Required: true},
			{Name: "secret_key", Label: "Secret API key (sk1_...)", Secret: true, Required: true},
		},
		Types:        []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes:        "The key only reaches domains with API access switched on at Porkbun: either for all domains at once, or in the settings of each domain. Porkbun raises a TTL under 60 seconds to 60; a record without a TTL gets 600. TXT values containing a backslash are refused: Porkbun's name servers drop it.",
		TXTForbidden: "\\",
		New: func(c map[string]string) any {
			return &porkbunProvider{APIKey: c["api_key"], SecretKey: c["secret_key"]}
		},
	})
	Register(Def{
		Name:  "vultr",
		Label: "Vultr",
		Fields: []contract.Field{
			{Name: "api_token", Label: "API key, preferably of a service user with only the Manage DNS policy", Secret: true, Required: true},
		},
		Types:        []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"},
		Notes:        "The account's API key reaches the whole account; prefer a service user of your organization with only the Manage DNS policy. Every key has its own API access control list: add the NethServer node's public address to it. Vultr's API is slow, a few seconds per request. Vultr raises a TTL under 60 seconds to 60; a record without a TTL gets 300. TXT values containing a double quote or a backslash are refused: Vultr does not accept the quote, and its name servers drop the backslash.",
		TXTForbidden: "\"\\",
		New: func(c map[string]string) any {
			return &vultrProvider{APIToken: c["api_token"]}
		},
	})
	Register(Def{
		Name:  "powerdns",
		Label: "PowerDNS (HTTP API)",
		Fields: []contract.Field{
			{Name: "api_url", Label: "API URL of the PowerDNS Authoritative server, for example https://ns1.example.com:8081", Required: true},
			{Name: "api_key", Label: "API key (the server's api-key setting)", Secret: true, Required: true},
			{Name: "server_id", Label: "Server id", Default: "localhost"},
		},
		Verify: func(c map[string]string) string {
			if _, err := pdBaseURL(c["api_url"], c["server_id"]); err != nil {
				return "api_url: " + err.Error()
			}
			return ""
		},
		Types: []string{"A", "AAAA", "CAA", "CNAME", "HTTPS", "MX", "NS", "SRV", "SVCB", "TXT"},
		Notes: "For a PowerDNS Authoritative server (4.x or 5.x) with its API switched on (api=yes, api-key, webserver=yes) and webserver-allow-from allowing the NethServer node. The key reaches every zone of the server; with http:// it crosses the network unencrypted, so prefer https:// through a reverse proxy, or a private network. Secondary zones are not listed. For the SOA serial to go up on each change, the zone needs SOA-EDIT-API (zones created through the API have it).",
		New: func(c map[string]string) any {
			return &powerDNSProvider{APIURL: c["api_url"], APIKey: c["api_key"], ServerID: c["server_id"]}
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
