package registry

import (
	"errors"
	"fmt"
	"testing"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

func TestRoute53ZoneNotFoundMapped(t *testing.T) {
	var ce *contract.Error
	err := route53Err("example.com.", fmt.Errorf("HostedZoneNotFound: No zones found for the domain example.com."))
	if !errors.As(err, &ce) || ce.Code != contract.CodeZoneNotFound {
		t.Fatalf("got %v", err)
	}
	other := errors.New("StatusCode: 403, AccessDenied")
	if route53Err("example.com.", other) != other {
		t.Fatal("other errors must pass through")
	}
	if route53Err("example.com.", nil) != nil {
		t.Fatal("nil must stay nil")
	}
}

// The package's client must be built from the given keys and the fixed
// region, never from the node's environment or ~/.aws.
func TestRoute53UsesGivenKeys(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "from-env")
	t.Setenv("AWS_REGION", "eu-west-3")
	p := newRoute53("AKIDEXAMPLE", "secret")
	if p.AccessKeyId != "AKIDEXAMPLE" || p.SecretAccessKey != "secret" || p.Region != route53Region {
		t.Fatalf("%+v", p.Provider)
	}
	if p.client.Options().Region != route53Region {
		t.Fatalf("zone-list client region %q", p.client.Options().Region)
	}
}
