package dnsops

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
	"github.com/danb35/ns8-dnshelper/helper/internal/txtfmt"
)

// Resolver finds a zone's name servers and their addresses; *net.Resolver
// is one.
type Resolver interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Limits of a propagation check.
const (
	maxServers         = 8
	maxAddrsPerServer  = 4
	propagationTimeout = 4 * time.Second
)

// CheckPropagation asks each of the zone's authoritative name servers, at
// each of its addresses and without recursion, for one name and type, and
// compares the answer with the records at the DNS host. The name servers are
// found through DNS (the zone's delegation), or, failing that, from the
// apex NS records the provider reports.
func (o *Ops) CheckPropagation(ctx context.Context, f *contract.Filter) (contract.Response, error) {
	if f == nil || f.Name == "" || f.Type == "" {
		return contract.Response{}, invalid("check-propagation needs a name and a type")
	}
	typ := strings.ToUpper(f.Type)
	qtype, ok := dns.StringToType[typ]
	if !ok {
		return contract.Response{}, invalid("unknown record type %q", f.Type)
	}
	name := normName(f.Name)
	es, err := o.read(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	var expected []contract.Record
	var apexNS []string
	for _, e := range es {
		if e.c.Name == name && e.c.Type == typ {
			expected = append(expected, e.c)
		}
		if e.c.Name == "@" && e.c.Type == "NS" {
			apexNS = append(apexNS, e.c.Data)
		}
	}

	res := o.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	zone := ZoneFQDN(o.Zone)
	hosts, source := []string{}, "dns"
	if ns, err := res.LookupNS(ctx, zone); err == nil {
		for _, n := range ns {
			hosts = append(hosts, n.Host)
		}
	}
	if len(hosts) == 0 {
		hosts, source = apexNS, "provider"
	}
	if len(hosts) == 0 {
		return contract.Response{}, &contract.Error{Code: contract.CodeZoneNotFound,
			Message: "no name servers found for the zone, neither in DNS nor at the DNS host"}
	}
	sort.Strings(hosts)
	if len(hosts) > maxServers {
		hosts = hosts[:maxServers]
	}

	fqdn := zone
	if name != "@" {
		fqdn = name + "." + zone
	}
	want := map[string]bool{}
	for _, r := range expected {
		want[normData(typ, r.Data)] = true
	}

	port := o.DNSPort
	if port == "" {
		port = "53"
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var out []contract.ServerCheck
	add := func(c contract.ServerCheck) {
		if c.Values == nil {
			c.Values = []string{} // the output schema wants a list
		}
		mu.Lock()
		out = append(out, c)
		mu.Unlock()
	}
	for _, h := range hosts {
		host := strings.TrimSuffix(strings.ToLower(h), ".")
		var addrs []string
		if ip := net.ParseIP(host); ip != nil {
			addrs = []string{ip.String()}
		} else if ips, err := res.LookupIPAddr(ctx, host); err != nil || len(ips) == 0 {
			add(contract.ServerCheck{Server: host, Status: "error", Message: "the name server's address cannot be found"})
			continue
		} else {
			for _, ip := range ips {
				addrs = append(addrs, ip.IP.String())
			}
			sort.Strings(addrs)
		}
		if len(addrs) > maxAddrsPerServer {
			addrs = addrs[:maxAddrsPerServer]
		}
		for _, a := range addrs {
			wg.Add(1)
			go func(host, addr string) {
				defer wg.Done()
				add(askServer(ctx, host, addr, port, fqdn, qtype, typ, want))
			}(host, a)
		}
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].Address < out[j].Address
	})
	return contract.Response{OK: true, Records: nonNil(expected), Servers: out, ServersFrom: source}, nil
}

// askServer queries one address of one name server.
func askServer(ctx context.Context, host, addr, port, fqdn string, qtype uint16, typ string, want map[string]bool) contract.ServerCheck {
	c := contract.ServerCheck{Server: host, Address: addr, Values: []string{}}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	m.RecursionDesired = false
	target := net.JoinHostPort(addr, port)
	client := &dns.Client{Timeout: propagationTimeout}
	r, _, err := client.ExchangeContext(ctx, m, target)
	if err == nil && r.Truncated {
		client.Net = "tcp"
		r, _, err = client.ExchangeContext(ctx, m, target)
	}
	switch {
	case err != nil:
		c.Status, c.Message = "error", "no answer"
		if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
			// the usual cause is the node, not the name server
			c.Message = "no answer over IPv6; this node may have no working IPv6"
		}
		return c
	case r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError:
		c.Status, c.Message = "error", "answered "+dns.RcodeToString[r.Rcode]
		return c
	case !r.Authoritative:
		c.Status, c.Message = "error", "not authoritative for the zone"
		return c
	}
	got := map[string]bool{}
	for _, rr := range r.Answer {
		h := rr.Header()
		if h.Rrtype != qtype || !strings.EqualFold(h.Name, dns.Fqdn(fqdn)) {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String()))
		if typ == "TXT" || typ == "SPF" {
			data = txtfmt.Unquote(data)
		}
		c.Values = append(c.Values, data)
		got[normData(typ, data)] = true
	}
	sort.Strings(c.Values)
	c.Status = "same"
	if len(got) != len(want) {
		c.Status = "different"
	}
	for v := range want {
		if !got[v] {
			c.Status = "different"
		}
	}
	if c.Status == "different" {
		c.Message = fmt.Sprintf("%d value(s) served, %d at the DNS host", len(got), len(want))
	}
	return c
}
