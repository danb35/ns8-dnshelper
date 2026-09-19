// Package zonelock serializes changes to a DNS zone with an flock(2) file
// lock. libdns assumes only one writer at a time and provides no locking.
package zonelock

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

var zoneRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$`)

// ValidZone reports whether zone is safe to use as a file name.
func ValidZone(zone string) bool { return zoneRe.MatchString(zone) && len(zone) <= 253 }

// Acquire takes an exclusive lock for zone under dir, waiting until ctx is
// done. The returned function releases it. The lock also dies with the process.
func Acquire(ctx context.Context, dir, zone string) (func(), error) {
	if !ValidZone(zone) {
		return nil, fmt.Errorf("invalid zone name %q", zone)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, zone+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK {
			_ = f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
