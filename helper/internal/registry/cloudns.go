package registry

import (
	"context"
	"strings"

	"github.com/libdns/cloudns"
	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// clouDNSProvider wraps the libdns ClouDNS package (v1.2.0), which targets the
// libdns v1 API and is used as it is:
//
//   - it sends every request as a POST form, so the password is never in a URL;
//   - MX and SRV priority, weight and port are sent as strings and always
//     present, 0 included (issue #19);
//   - records have IDs: deletes remove only exact matches, and SetRecords
//     replaces the (name, type) set, keeping records that already match;
//   - TTLs are rounded up to the next value ClouDNS allows (60, 300, 900,
//     1800, 3600, 21600, ...).
//
// ClouDNS answers HTTP 200 with {"status":"Failed","statusDescription":...}
// for every refusal, which the package passes on as text; this wrapper turns
// the ones dnshelper reports specially into structured errors.
type clouDNSProvider struct{ *cloudns.Provider }

func newClouDNS(c map[string]string) clouDNSProvider {
	return clouDNSProvider{&cloudns.Provider{
		AuthId:       c["auth_id"],
		SubAuthId:    c["sub_auth_id"],
		SubAuthUser:  c["sub_auth_user"],
		AuthPassword: c["auth_password"],
	}}
}

// clouDNSVerify requires exactly one of the three login fields.
func clouDNSVerify(c map[string]string) string {
	n := 0
	for _, f := range []string{"auth_id", "sub_auth_id", "sub_auth_user"} {
		if c[f] != "" {
			n++
		}
	}
	if n != 1 {
		return "give exactly one of auth_id, sub_auth_id and sub_auth_user"
	}
	return ""
}

// clouDNSError maps ClouDNS's refusals. Its messages never contain the
// password; the package adds only the zone and record names.
func clouDNSError(err error) error {
	if err == nil {
		return nil
	}
	low := strings.ToLower(err.Error())
	switch {
	case strings.Contains(low, "invalid authentication"):
		return &contract.Error{Code: contract.CodeAuthFailed,
			Message: "ClouDNS refused the login: check the API user or sub-user and its password, and the IP address allowed for it"}
	case strings.Contains(low, "missing domain-name") || strings.Contains(low, "zone not found") ||
		strings.Contains(low, "domain not found") || strings.Contains(low, "invalid domain-name"):
		return &contract.Error{Code: contract.CodeZoneNotFound, Message: "ClouDNS has no such zone for this API user"}
	}
	return err
}

func (p clouDNSProvider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	z, err := p.Provider.ListZones(ctx)
	return z, clouDNSError(err)
}

func (p clouDNSProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	r, err := p.Provider.GetRecords(ctx, zone)
	return r, clouDNSError(err)
}

func (p clouDNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	r, err := p.Provider.AppendRecords(ctx, zone, recs)
	return r, clouDNSError(err)
}

func (p clouDNSProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	r, err := p.Provider.SetRecords(ctx, zone, recs)
	return r, clouDNSError(err)
}

func (p clouDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	r, err := p.Provider.DeleteRecords(ctx, zone, recs)
	return r, clouDNSError(err)
}
