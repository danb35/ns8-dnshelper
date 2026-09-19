package dnsops

import (
	"fmt"
	"sort"
	"strings"

	"github.com/libdns/libdns"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// Plan is the computed effect of an operation, before any provider write.
type Plan struct {
	Add    []contract.Record
	Remove []contract.Record
	// Desired is the complete new membership of every touched (name, type)
	// RRset. Only set-records uses it (it is what SetRecords is called with).
	Desired []contract.Record
	// After is the whole zone as it will be once the plan is applied.
	After []contract.Record
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool { return len(p.Add) == 0 && len(p.Remove) == 0 }

func checkForbidden(r contract.Record) error {
	if r.Type == "SOA" {
		return &contract.Error{Code: contract.CodeForbidden, Message: "SOA records are managed by the DNS host and cannot be changed"}
	}
	if r.Type == "NS" && r.Name == "@" {
		return &contract.Error{Code: contract.CodeForbidden, Message: "apex NS records cannot be changed"}
	}
	return nil
}

// PlanAppend adds the input records that are not already present.
func PlanAppend(existing, input []contract.Record) (Plan, error) {
	var p Plan
	for _, r := range input {
		if err := checkForbidden(r); err != nil {
			return p, err
		}
		if !contains(existing, r) && !contains(p.Add, r) {
			p.Add = append(p.Add, r)
		}
	}
	p.After = append(append([]contract.Record{}, existing...), p.Add...)
	return p, nil
}

// PlanSet computes a set-records change. See contract.ModeMerge / ModeRRset.
func PlanSet(existing, input []contract.Record, mode string, replacePrefixes []string) (Plan, error) {
	var p Plan
	if mode == "" {
		mode = contract.ModeMerge
	}
	if mode != contract.ModeMerge && mode != contract.ModeRRset {
		return p, invalid("unknown set-records mode %q", mode)
	}
	touched := map[string]bool{}
	for _, r := range input {
		if err := checkForbidden(r); err != nil {
			return p, err
		}
		touched[groupKey(r)] = true
	}

	inputKeys := map[string]bool{}
	for _, r := range input {
		inputKeys[key(r)] = true
	}
	var kept []contract.Record
	if mode == contract.ModeMerge {
		for _, e := range existing {
			// A same-valued record is replaced whatever its TTL: that is how
			// a TTL is changed.
			if !touched[groupKey(e)] || inputKeys[key(e)] || hasAnyPrefix(e.Data, replacePrefixes) {
				continue
			}
			kept = append(kept, e)
		}
	}
	for _, r := range append(kept, input...) {
		// Prefer the existing record when the input matches it, so that its
		// TTL is kept when the input leaves the TTL unspecified.
		for _, e := range existing {
			if same(e, r) {
				r = e
				break
			}
		}
		if !contains(p.Desired, r) {
			p.Desired = append(p.Desired, r)
		}
	}

	var oldTouched []contract.Record
	for _, e := range existing {
		if touched[groupKey(e)] {
			oldTouched = append(oldTouched, e)
		} else {
			p.After = append(p.After, e)
		}
	}
	for _, d := range p.Desired {
		if !contains(oldTouched, d) {
			p.Add = append(p.Add, d)
		}
	}
	for _, e := range oldTouched {
		if !contains(p.Desired, e) {
			p.Remove = append(p.Remove, e)
		}
	}
	p.After = append(p.After, p.Desired...)
	return p, nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// PlanDelete resolves the input against the existing records. Input fields
// type, data and ttl are optional filters, as in libdns DeleteRecords, but they
// are resolved here so that the provider is only ever handed concrete records.
func PlanDelete(existing, input []contract.Record) (Plan, error) {
	var p Plan
	for _, in := range input {
		if err := checkForbidden(in); err != nil {
			return p, err
		}
		if in.Type == "" && in.Data == "" && in.Name == "@" {
			return p, &contract.Error{Code: contract.CodeForbidden, Message: "refusing to delete every record at the zone apex; give a type"}
		}
		for _, e := range existing {
			if normName(e.Name) != in.Name {
				continue
			}
			if in.Type != "" && e.Type != in.Type {
				continue
			}
			if in.Data != "" && normData(e.Type, e.Data) != normData(in.Type, in.Data) {
				continue
			}
			if in.TTL != 0 && e.TTL != in.TTL {
				continue
			}
			if err := checkForbidden(e); err != nil {
				return p, err
			}
			if !contains(p.Remove, e) {
				p.Remove = append(p.Remove, e)
			}
		}
	}
	for _, e := range existing {
		if !contains(p.Remove, e) {
			p.After = append(p.After, e)
		}
	}
	return p, nil
}

// CheckAfter verifies that the records a plan adds leave the zone valid: no
// CNAME next to other data or at the apex, and no MX/SRV target that is a CNAME.
// Problems that already exist elsewhere in the zone are not this plan's business.
func CheckAfter(zone string, p Plan) error {
	byName := map[string]map[string][]contract.Record{}
	for _, r := range p.After {
		n := normName(r.Name)
		if byName[n] == nil {
			byName[n] = map[string][]contract.Record{}
		}
		byName[n][r.Type] = append(byName[n][r.Type], r)
	}
	touched := map[string]bool{}
	for _, r := range p.Add {
		touched[normName(r.Name)] = true
	}
	names := make([]string, 0, len(touched))
	for n := range touched {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		types := byName[n]
		cn := types["CNAME"]
		if len(cn) == 0 {
			continue
		}
		conflict := func(msg string, a ...any) error {
			return &contract.Error{Code: contract.CodeConflict, Message: fmt.Sprintf(msg, a...)}
		}
		if n == "@" {
			return conflict("a CNAME cannot exist at the zone apex")
		}
		if len(cn) > 1 {
			return conflict("%s would have more than one CNAME", n)
		}
		for t := range types {
			if t != "CNAME" {
				return conflict("%s has a CNAME, which cannot coexist with %s records", n, t)
			}
		}
	}
	z := zoneBare(zone)
	for _, r := range p.Add {
		if r.Type != "SRV" && r.Type != "MX" {
			continue
		}
		f := strings.Fields(r.Data)
		if len(f) == 0 {
			continue
		}
		target := strings.ToLower(strings.TrimSuffix(f[len(f)-1], "."))
		var rel string
		switch {
		case target == z:
			rel = "@"
		case strings.HasSuffix(target, "."+z):
			rel = libdns.RelativeName(target, z)
		default:
			continue
		}
		if len(byName[rel]["CNAME"]) > 0 {
			return &contract.Error{Code: contract.CodeConflict,
				Message: fmt.Sprintf("%s target %s is a CNAME, which is not allowed", r.Type, target)}
		}
	}
	return nil
}
