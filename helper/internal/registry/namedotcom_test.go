package registry

import (
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestNameComRaisesShortTTLs(t *testing.T) {
	in := []libdns.Record{
		libdns.RR{Name: "a", Type: "TXT", Data: "x"},
		libdns.RR{Name: "b", Type: "TXT", Data: "y", TTL: 60 * time.Second},
		libdns.RR{Name: "c", Type: "TXT", Data: "z", TTL: time.Hour},
	}
	out := withMinTTL(in)
	for i, want := range []time.Duration{300 * time.Second, 300 * time.Second, time.Hour} {
		if got := out[i].RR().TTL; got != want {
			t.Errorf("record %d: TTL %v, want %v", i, got, want)
		}
	}
}
