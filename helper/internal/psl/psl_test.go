package psl

import (
	"reflect"
	"testing"
)

func zones(names ...string) []string {
	var out []string
	for _, c := range Candidates(names) {
		out = append(out, c.Zone)
	}
	return out
}

func TestReducesToRegistrableDomains(t *testing.T) {
	got := Candidates([]string{"mail.example.com", "WWW.Example.com.", "example.com", "shop.example.co.uk", "*.wild.example.org", "a.b.c.example.net"})
	want := map[string][]string{
		"example.com":   {"example.com", "mail.example.com", "www.example.com"},
		"example.co.uk": {"shop.example.co.uk"},
		"example.org":   {"wild.example.org"},
		"example.net":   {"a.b.c.example.net"},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for _, c := range got {
		if !reflect.DeepEqual(c.Names, want[c.Zone]) {
			t.Errorf("%s: %v", c.Zone, c.Names)
		}
	}
	if z := zones("b.example.com", "a.example.org"); !reflect.DeepEqual(z, []string{"example.com", "example.org"}) {
		t.Fatalf("result must be sorted: %v", z)
	}
}

func TestDropsNamesThatCannotBePublicZones(t *testing.T) {
	for _, n := range []string{"", "localhost", "192.168.1.5", "2001:db8::1", "nas.lan", "printer.local", "x.test",
		"com", "co.uk", "has space.example.com", "user@example.com", "_dmarc.example.com", "http://example.com"} {
		if z := zones(n); len(z) != 0 {
			t.Errorf("%q should be dropped, gave %v", n, z)
		}
	}
}

func TestPrivateSuffixesAreRespected(t *testing.T) {
	// github.io is a private-section suffix: every user owns a registrable name under it.
	if z := zones("me.github.io", "www.me.github.io"); !reflect.DeepEqual(z, []string{"me.github.io"}) {
		t.Fatalf("%v", z)
	}
}

func TestInternationalisedNamesAreKeptAsGiven(t *testing.T) {
	if z := zones("www.bücher.de"); !reflect.DeepEqual(z, []string{"bücher.de"}) {
		t.Fatalf("%v", z)
	}
}
