package dnsops

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
	"github.com/danb35/ns8-dnshelper/helper/internal/fakedns"
)

// testServer is an authoritative DNS server on 127.0.0.1 answering from a
// map of "name TYPE" to records in presentation format.
func testServer(t *testing.T, authoritative bool, answers map[string][]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = authoritative
		q := req.Question[0]
		for _, s := range answers[strings.ToLower(q.Name)+" "+dns.TypeToString[q.Qtype]] {
			rr, err := dns.NewRR(q.Name + " 300 IN " + dns.TypeToString[q.Qtype] + " " + s)
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	return port
}

type fakeResolver struct {
	ns    []string
	nsErr error
	ips   map[string][]string
}

func (r fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	if r.nsErr != nil {
		return nil, r.nsErr
	}
	var out []*net.NS
	for _, h := range r.ns {
		out = append(out, &net.NS{Host: h})
	}
	return out, nil
}

func (r fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, s := range r.ips[strings.TrimSuffix(host, ".")] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	if out == nil {
		return nil, errors.New("no such host")
	}
	return out, nil
}

func propagationZone() *fakedns.Fake {
	f := fakedns.New(zone)
	f.Seed(libdns.RR{Name: "www", Type: "A", TTL: 300 * time.Second, Data: "192.0.2.1"},
		libdns.RR{Name: "www", Type: "A", TTL: 300 * time.Second, Data: "192.0.2.2"},
		libdns.RR{Name: "@", Type: "TXT", TTL: 300 * time.Second, Data: `say "hi"`},
		libdns.RR{Name: "@", Type: "NS", TTL: 300 * time.Second, Data: "ns9.example.com."})
	return f
}

func TestPropagationSameAndDifferent(t *testing.T) {
	port := testServer(t, true, map[string][]string{
		"www.example.com. A": {"192.0.2.2", "192.0.2.1"},
		"example.com. TXT":   {`"say \"hi\""`},
	})
	o := &Ops{Provider: propagationZone(), Zone: zone, DNSPort: port,
		Resolver: fakeResolver{ns: []string{"ns1.example.com."}, ips: map[string][]string{"ns1.example.com": {"127.0.0.1"}}}}
	ctx := context.Background()

	r := ok(t)(o.CheckPropagation(ctx, &contract.Filter{Name: "www", Type: "A"}))
	if r.ServersFrom != "dns" || len(r.Servers) != 1 || r.Servers[0].Status != "same" || len(r.Records) != 2 {
		t.Fatalf("A: %+v", r)
	}
	if strings.Join(r.Servers[0].Values, ",") != "192.0.2.1,192.0.2.2" {
		t.Errorf("values: %v", r.Servers[0].Values)
	}
	r = ok(t)(o.CheckPropagation(ctx, &contract.Filter{Name: "@", Type: "TXT"}))
	if r.Servers[0].Status != "same" || r.Servers[0].Values[0] != `say "hi"` {
		t.Fatalf("TXT: %+v", r.Servers)
	}
	// a name the server does not serve yet
	r = ok(t)(o.CheckPropagation(ctx, &contract.Filter{Name: "www", Type: "AAAA"}))
	if r.Servers[0].Status != "same" {
		t.Errorf("nothing at the host, nothing served: %+v", r.Servers)
	}
	f := propagationZone()
	f.Seed(libdns.RR{Name: "new", Type: "CNAME", TTL: 300 * time.Second, Data: "web.example.net."})
	o.Provider = f
	r = ok(t)(o.CheckPropagation(ctx, &contract.Filter{Name: "new", Type: "CNAME"}))
	if r.Servers[0].Status != "different" || r.Servers[0].Message == "" {
		t.Errorf("not served yet: %+v", r.Servers)
	}
}

func TestPropagationErrorsAndFallback(t *testing.T) {
	port := testServer(t, false, map[string][]string{"www.example.com. A": {"192.0.2.1", "192.0.2.2"}})
	ctx := context.Background()
	// no delegation in DNS: the provider's apex NS records are used
	o := &Ops{Provider: propagationZone(), Zone: zone, DNSPort: port,
		Resolver: fakeResolver{nsErr: errors.New("NXDOMAIN"), ips: map[string][]string{"ns9.example.com": {"127.0.0.1"}}}}
	r := ok(t)(o.CheckPropagation(ctx, &contract.Filter{Name: "www", Type: "A"}))
	if r.ServersFrom != "provider" || r.Servers[0].Server != "ns9.example.com" {
		t.Fatalf("fallback: %+v", r)
	}
	if r.Servers[0].Status != "error" || !strings.Contains(r.Servers[0].Message, "not authoritative") {
		t.Errorf("a non-authoritative answer is an error: %+v", r.Servers)
	}
	// a server whose address is unknown, and one that does not answer
	o.Resolver = fakeResolver{ns: []string{"gone.example.net.", "127.0.0.1"}}
	o.DNSPort = "1" // nothing listens there
	r = ok(t)(o.CheckPropagation(ctx, &contract.Filter{Name: "www", Type: "A"}))
	if len(r.Servers) != 2 || r.Servers[0].Status != "error" || r.Servers[1].Status != "error" {
		t.Fatalf("errors: %+v", r.Servers)
	}
	_, err := o.CheckPropagation(ctx, &contract.Filter{Name: "www"})
	wantCode(t, err, "invalid_request")
	_, err = o.CheckPropagation(ctx, &contract.Filter{Name: "www", Type: "NOPE"})
	wantCode(t, err, "invalid_request")
}
