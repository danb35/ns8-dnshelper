// Package psl reduces host names to the registrable domains that contain them,
// using the Public Suffix List compiled into golang.org/x/net/publicsuffix.
package psl

import (
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// Candidates groups names by registrable domain (eTLD+1). Names that cannot
// belong to a public DNS zone are dropped: IP addresses, single labels, names
// that are themselves a public suffix, and names under a top-level domain the
// list does not know (.lan, .local, .test, ...), which a DNS host cannot serve.
// A leading "*." is ignored. The result is sorted; so is each name list.
func Candidates(names []string) []contract.Candidate {
	byZone := map[string]map[string]bool{}
	for _, raw := range names {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		n = strings.TrimPrefix(n, "*.")
		zone, ok := registrable(n)
		if !ok {
			continue
		}
		if byZone[zone] == nil {
			byZone[zone] = map[string]bool{}
		}
		byZone[zone][n] = true
	}
	out := make([]contract.Candidate, 0, len(byZone))
	for zone, set := range byZone {
		c := contract.Candidate{Zone: zone, Names: make([]string, 0, len(set))}
		for n := range set {
			c.Names = append(c.Names, n)
		}
		sort.Strings(c.Names)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Zone < out[j].Zone })
	return out
}

func registrable(n string) (string, bool) {
	if n == "" || !strings.Contains(n, ".") || strings.ContainsAny(n, " /:@_") {
		return "", false
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return "", false
	}
	suffix, icann := publicsuffix.PublicSuffix(n)
	if suffix == n {
		return "", false // the name is a public suffix itself
	}
	if !icann && !strings.Contains(suffix, ".") {
		return "", false // unknown top-level domain: the list's default rule, not a real one
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(n)
	if err != nil {
		return "", false
	}
	return zone, true
}
