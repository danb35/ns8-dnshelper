package zonelock

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSecondAcquireWaitsForRelease(t *testing.T) {
	dir := t.TempDir()
	release, err := Acquire(context.Background(), dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	short, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := Acquire(short, dir, "example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held lock should block, got %v", err)
	}

	// Another zone is independent.
	other, err := Acquire(context.Background(), dir, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	other()

	release()
	again, err := Acquire(context.Background(), dir, "example.com")
	if err != nil {
		t.Fatalf("lock should be free after release: %v", err)
	}
	again()
}

func TestZoneNameCannotEscapeTheDirectory(t *testing.T) {
	for _, z := range []string{"../x", "a/b", "", ".hidden"} {
		if _, err := Acquire(context.Background(), t.TempDir(), z); err == nil {
			t.Errorf("zone %q should be rejected", z)
		}
	}
}
