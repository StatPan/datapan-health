package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const dataGoKRObserverBinaryName = "datapan-health-data-go-kr-observer"
const dataGoKRObserverBinaryPath = "/" + dataGoKRObserverBinaryName

var observationCredentialEnvironmentNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// dataGoKRObserverBinary is the immutable identity of the one Health-owned
// executable that the bounded worker may launch. There are intentionally no
// arguments, URL, provider, or operation fields: the binary itself owns the
// fixed data.go.kr rotating-shard scope.
type dataGoKRObserverBinary struct {
	Path               string
	SHA256             string
	BuildRevision      string
	CredentialEnvNames []string
}

// DataGoKRObservationWorker is the only operational entrance for the bounded
// provider observation path. It binds a verified Health-owned binary to the
// #32 plan environment and delegates process containment to the private
// boundedObservationRunner.
type DataGoKRObservationWorker struct {
	Producer            ObservationRunProducer
	Registry            ObservationRunRegistry
	Binding             ObservationBindingGuard
	BatchSize           int
	MaxParallel         int
	Timeout             time.Duration
	OutputRoot          string
	BinarySHA256        string
	BinaryBuildRevision string
	CredentialEnvNames  []string
	Now                 func() time.Time

	// observerPath is test-only. Production always uses the fixed image path;
	// no external or operational caller can select a process path or args.
	observerPath string
}

func (w DataGoKRObservationWorker) Run(ctx context.Context, runID string, plans []ObservationShardPlan) (BoundedObservationRun, error) {
	if !validDataGoKRObservationWorker(w) {
		return BoundedObservationRun{}, errors.New("data.go.kr observation worker input is invalid")
	}
	now := w.Now
	if now == nil {
		now = time.Now
	}
	cleanup, err := CleanupExpiredBoundedObservationRuns(w.OutputRoot, now().UTC(), BoundedObservationRetentionTTL)
	if err != nil {
		return BoundedObservationRun{}, errors.New("data.go.kr observation cleanup is unsafe")
	}
	producer := w.Producer
	producer.Observer = &ObservationRunObserver{BinarySHA256: w.BinarySHA256, BuildRevision: w.BinaryBuildRevision}
	return boundedObservationRunner{
		Producer:    producer,
		Registry:    w.Registry,
		Binding:     w.Binding,
		BatchSize:   w.BatchSize,
		MaxParallel: w.MaxParallel,
		Timeout:     w.Timeout,
		OutputRoot:  w.OutputRoot,
		command: observationCommandSpec{
			Path:        w.dataGoKRObserverPath(),
			Environment: selectEnvironment(w.CredentialEnvNames),
		},
		Cleanup: &cleanup,
		Now:     now,
	}.Run(ctx, runID, plans)
}

func validDataGoKRObservationWorker(worker DataGoKRObservationWorker) bool {
	binary := dataGoKRObserverBinary{Path: worker.dataGoKRObserverPath(), SHA256: worker.BinarySHA256, BuildRevision: worker.BinaryBuildRevision, CredentialEnvNames: worker.CredentialEnvNames}
	if !validObservationRunProducer(worker.Producer) || worker.Producer.Observer != nil || !validDataGoKRObserverBinary(binary) {
		return false
	}
	return worker.BinaryBuildRevision == worker.Producer.Revision
}

func (worker DataGoKRObservationWorker) dataGoKRObserverPath() string {
	if worker.observerPath != "" {
		return worker.observerPath
	}
	return dataGoKRObserverBinaryPath
}

func validDataGoKRObserverBinary(binary dataGoKRObserverBinary) bool {
	if filepath.Base(binary.Path) != dataGoKRObserverBinaryName || !sha256Pattern.MatchString(binary.SHA256) || !commitPattern.MatchString(binary.BuildRevision) || !validObservationCredentialEnvironmentNames(binary.CredentialEnvNames) {
		return false
	}
	info, err := os.Lstat(binary.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0o111 == 0 {
		return false
	}
	digest, err := digestDataGoKRObserverBinary(binary.Path)
	return err == nil && digest == binary.SHA256
}

func digestDataGoKRObserverBinary(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", os.ErrPermission
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validObservationCredentialEnvironmentNames(names []string) bool {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !observationCredentialEnvironmentNamePattern.MatchString(name) || strings.HasPrefix(name, boundedObservationReservedEnvironmentPrefix) || name == "GATUS_TOKEN" || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}
