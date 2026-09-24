package registry

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	r53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/libdns/libdns"
	"github.com/libdns/route53"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// route53Region is where the Route 53 API is served; the service is global.
const route53Region = "us-east-1"

// route53Provider adapts the libdns Route 53 package (v1.6.2):
//
//   - it has no zone list, so ListZones is added here (public hosted zones
//     only), for the wizard;
//   - it reports a zone it cannot find as a plain error, mapped here to
//     zone_not_found.
//
// The package writes whole record sets with Route 53's own UPSERT and DELETE,
// and sends every value as one text string (SRV "0 0 443 target."), so the
// zero-value bug of issue #19 cannot occur. Its delete matches exact values
// only; dnshelper always hands it complete records it has just read.
type route53Provider struct {
	*route53.Provider
	client *r53.Client // for ListZones; the package's own client is unexported
}

func newRoute53(keyID, secret string) route53Provider {
	creds := credentials.NewStaticCredentialsProvider(keyID, secret, "")
	return route53Provider{
		// With both keys and the region given, the SDK uses them rather than
		// the node's environment or ~/.aws.
		Provider: &route53.Provider{AccessKeyId: keyID, SecretAccessKey: secret, Region: route53Region},
		client:   r53.New(r53.Options{Region: route53Region, Credentials: aws.NewCredentialsCache(creds)}),
	}
}

func route53Err(zone string, err error) error {
	if err != nil && strings.Contains(err.Error(), "HostedZoneNotFound") {
		return &contract.Error{Code: contract.CodeZoneNotFound,
			Message: "Route 53 has no hosted zone " + strings.TrimSuffix(zone, ".") + " that these credentials can see"}
	}
	return err
}

// ListZones lists the public hosted zones. Credentials without
// route53:ListHostedZones get "unsupported", so the wizard asks for the zone.
func (p route53Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	var zones []libdns.Zone
	pages := r53.NewListHostedZonesPaginator(p.client, &r53.ListHostedZonesInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "AccessDenied") {
				return nil, &contract.Error{Code: contract.CodeUnsupported, Message: "these AWS credentials are not allowed to list hosted zones"}
			}
			return nil, err
		}
		for _, z := range page.HostedZones {
			if z.Config != nil && z.Config.PrivateZone {
				continue
			}
			zones = append(zones, libdns.Zone{Name: aws.ToString(z.Name)})
		}
	}
	return zones, nil
}

func (p route53Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := p.Provider.GetRecords(ctx, zone)
	return recs, route53Err(zone, err)
}

func (p route53Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	out, err := p.Provider.AppendRecords(ctx, zone, recs)
	return out, route53Err(zone, err)
}

func (p route53Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	out, err := p.Provider.SetRecords(ctx, zone, recs)
	return out, route53Err(zone, err)
}

func (p route53Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	out, err := p.Provider.DeleteRecords(ctx, zone, recs)
	return out, route53Err(zone, err)
}
