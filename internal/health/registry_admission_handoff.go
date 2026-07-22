package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RegistryAdmissionHandoff is a byte-level producer export. It intentionally
// does not load, vendor, or execute Registry schema, policy, or validator code.
// Registry remains the only authority that can admit an outer envelope.
type RegistryAdmissionHandoff struct {
	Aggregate HandoffArtifact
	Shards    []HandoffArtifact
}

type HandoffArtifact struct {
	Path   string
	SHA256 string
	Bytes  []byte
}

// HandoffGuard is caller-owned freshness and immutable binding authorization.
// The exporter never selects the reference time or maximum age.
type HandoffGuard struct {
	ExpectedHealthRevision string
	ExpectedRegistry       ObservationRunRegistry
	ReferenceAt            time.Time
	MaxAge                 time.Duration
}

// BuildRegistryAdmissionHandoff binds actual Health aggregate and shard bytes
// to the immutable producer-artifact layout expected by Registry #591. It is
// a local export safety check, not a Registry admission decision.
func BuildRegistryAdmissionHandoff(aggregate []byte, sourceRoot string, guard HandoffGuard) (RegistryAdmissionHandoff, error) {
	run, err := DecodeBoundedObservationRun(bytes.NewReader(aggregate))
	if err != nil || !validHandoffGuard(run, guard) || run.Aggregate.Completeness != "complete" || run.Aggregate.TimedOut {
		return RegistryAdmissionHandoff{}, errors.New("bounded observation handoff is incomplete")
	}
	handoff := RegistryAdmissionHandoff{Aggregate: HandoffArtifact{Path: filepath.ToSlash(filepath.Join("runs", run.Run.RunID+".json")), SHA256: digestHandoffBytes(aggregate), Bytes: append([]byte(nil), aggregate...)}, Shards: make([]HandoffArtifact, 0, len(run.Shards))}
	for _, shard := range run.Shards {
		if !shard.Completed || !shard.ReceiptAvailable {
			return RegistryAdmissionHandoff{}, errors.New("bounded observation handoff is incomplete")
		}
		data, err := readBoundedObservationHandoffArtifact(sourceRoot, shard.ReceiptPath)
		if err != nil || digestHandoffBytes(data) != shard.ReceiptSHA256 || !bytes.Equal(data, canonicalObservationShardArtifact(shard.Index, shard.TerminalState)) {
			return RegistryAdmissionHandoff{}, errors.New("bounded observation handoff bytes are invalid")
		}
		handoff.Shards = append(handoff.Shards, HandoffArtifact{Path: fmt.Sprintf("shards/%d/receipt.json", shard.Index), SHA256: shard.ReceiptSHA256, Bytes: data})
	}
	sort.Slice(handoff.Shards, func(i, j int) bool { return handoff.Shards[i].Path < handoff.Shards[j].Path })
	return handoff, nil
}

func validHandoffGuard(run BoundedObservationRun, guard HandoffGuard) bool {
	if !commitPattern.MatchString(guard.ExpectedHealthRevision) || !validObservationRunRegistry(guard.ExpectedRegistry) || guard.ReferenceAt.IsZero() || guard.MaxAge <= 0 || run.Producer.Revision != guard.ExpectedHealthRevision || run.Registry != guard.ExpectedRegistry {
		return false
	}
	return run.ValidateAt(guard.ReferenceAt, guard.MaxAge) == nil
}

func readBoundedObservationHandoffArtifact(root, path string) ([]byte, error) {
	if filepath.IsAbs(path) {
		return nil, os.ErrPermission
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}
	parts := strings.Split(filepath.ToSlash(clean), "/")
	if len(parts) != 3 || parts[0] != "shards" || parts[2] != "receipt.json" {
		return nil, os.ErrPermission
	}
	for _, directory := range []string{root, filepath.Join(root, parts[0]), filepath.Join(root, parts[0], parts[1])} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, os.ErrPermission
		}
	}
	filePath := filepath.Join(root, filepath.FromSlash(clean))
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64*1024 {
		return nil, os.ErrPermission
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return nil, os.ErrPermission
	}
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		return nil, os.ErrPermission
	}
	return data, nil
}

func digestHandoffBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
