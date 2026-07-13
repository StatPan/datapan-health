package health

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type ReceiptSink interface {
	Store(context.Context, Receipt) error
}

type LocalSink struct {
	path string
	mu   sync.Mutex
}

func NewLocalSink(path string) *LocalSink { return &LocalSink{path: path} }

func (s *LocalSink) Store(ctx context.Context, receipt Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(receipt); err != nil {
		return fmt.Errorf("encode receipt: %w", err)
	}
	return f.Sync()
}
