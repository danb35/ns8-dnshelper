// Package registry is the curated list of DNS providers dnshelper supports:
// each entry pairs a constructor with the credential fields a UI must ask for.
// Provider structs are deliberately not inspected by reflection; their field
// names vary and some fields are not credentials.
package registry

import (
	"fmt"
	"sort"
	"strings"

	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

// Def describes one supported provider.
type Def struct {
	Name   string
	Label  string
	Fields []contract.Field
	// Types are the record types the provider package is documented or tested
	// to handle. They are declared here, not discovered: libdns has no way to
	// ask a provider what it supports.
	Types []string
	Notes string
	// TXTForbidden lists characters the provider package cannot store in a TXT
	// value without corrupting it; append and set requests containing one are
	// refused.
	TXTForbidden string
	// Verify, when set, checks combinations of fields that Required cannot
	// express (one of several alternatives). It returns a message naming fields,
	// never values, or "" when the credential is usable.
	Verify func(cred map[string]string) string
	// New builds the libdns provider from credential values keyed by field
	// name. It does not validate them; use Check for that.
	New func(cred map[string]string) any
}

var defs = map[string]Def{}

// Register adds a provider. It panics on a duplicate name.
func Register(d Def) {
	if _, dup := defs[d.Name]; dup {
		panic("registry: duplicate provider " + d.Name)
	}
	defs[d.Name] = d
}

// Get returns the provider with the given name.
func Get(name string) (Def, bool) {
	d, ok := defs[name]
	return d, ok
}

// All returns every provider sorted by name.
func All() []Def {
	out := make([]Def, 0, len(defs))
	for _, d := range defs {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Info returns the list-providers description of d.
func (d Def) Info() contract.ProviderInfo {
	return contract.ProviderInfo{Name: d.Name, Label: d.Label, Fields: d.Fields, Types: d.Types, Notes: d.Notes}
}

// Check verifies cred against the provider's field list and returns cred with
// defaults filled in. Its errors name fields, never values.
func (d Def) Check(cred map[string]string) (map[string]string, error) {
	known := map[string]contract.Field{}
	for _, f := range d.Fields {
		known[f.Name] = f
	}
	out := map[string]string{}
	for k, v := range cred {
		if _, ok := known[k]; !ok {
			return nil, &contract.Error{Code: contract.CodeInvalidRequest, Message: fmt.Sprintf("unknown credential field %q for provider %s", k, d.Name)}
		}
		out[k] = v
	}
	var missing []string
	for _, f := range d.Fields {
		if out[f.Name] == "" && f.Default != "" {
			out[f.Name] = f.Default
		}
		if f.Required && out[f.Name] == "" {
			missing = append(missing, f.Name)
		}
	}
	if len(missing) > 0 {
		return nil, &contract.Error{Code: contract.CodeInvalidRequest, Message: "missing credential fields: " + strings.Join(missing, ", ")}
	}
	if d.Verify != nil {
		if msg := d.Verify(out); msg != "" {
			return nil, &contract.Error{Code: contract.CodeInvalidRequest, Message: msg}
		}
	}
	return out, nil
}

// Secrets returns the values of the fields marked secret, for error scrubbing.
// Every credential value is treated as sensitive when the field is unknown.
func (d Def) Secrets(cred map[string]string) []string {
	secret := map[string]bool{}
	for _, f := range d.Fields {
		secret[f.Name] = f.Secret
	}
	var out []string
	for k, v := range cred {
		if v != "" && (secret[k] || !knownField(d, k)) {
			out = append(out, v)
		}
	}
	return out
}

func knownField(d Def, name string) bool {
	for _, f := range d.Fields {
		if f.Name == name {
			return true
		}
	}
	return false
}
