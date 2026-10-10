package health

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

var errContextFileLockUnavailable = errors.New("context-aware file lock unavailable")

// flockExclusiveContext acquires a local shared-filesystem flock without
// blocking beyond the caller's deadline. It is suitable only for the local
// filesystem contract documented by the attempt and quota stores; it does not
// provide a multi-host lease.
func flockExclusiveContext(ctx context.Context, file *os.File) error {
	if ctx == nil || file == nil {
		return errContextFileLockUnavailable
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
