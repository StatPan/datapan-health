package health

import (
	"errors"
	"sync"
	"time"
)

// ScheduleCoverageLifecycleConfig is the full-population, dry-run-only
// scheduler input. It deliberately has no ProbeRunner, credentials, endpoint,
// or delivery dependency: activating it can create coverage evidence but can
// never execute a provider request.
type ScheduleCoverageLifecycleConfig struct {
	StatePath           string
	ManifestPath        string
	ReleaseManifestPath string
	ReceiptPath         string
	ShardCount          int
	DryRun              bool
}

// ScheduleCoverageLifecycle is owned by the health-scheduler process so that
// the same acceptance loop that manages canary cadence also produces durable,
// full-population schedule coverage evidence. It is intentionally separate
// from canary execution and never calls a provider.
type ScheduleCoverageLifecycle struct {
	mu           sync.Mutex
	statePath    string
	manifest     OperationManifest
	receipt      OperationManifestReceipt
	shardCount   int
	lastInterval time.Time
}

func NewScheduleCoverageLifecycle(config ScheduleCoverageLifecycleConfig) (*ScheduleCoverageLifecycle, error) {
	if !config.DryRun || config.StatePath == "" || config.ShardCount < 1 || config.ManifestPath == "" || config.ReleaseManifestPath == "" || config.ReceiptPath == "" {
		return nil, errors.New("schedule coverage lifecycle is not dry-run ready")
	}
	manifest, receipt, err := LoadPinnedOperationManifest(config.ManifestPath, config.ReleaseManifestPath, config.ReceiptPath)
	if err != nil {
		return nil, errors.New("schedule coverage lifecycle manifest is invalid")
	}
	return &ScheduleCoverageLifecycle{statePath: config.StatePath, manifest: manifest, receipt: receipt, shardCount: config.ShardCount}, nil
}

// ProcessDue records one durable schedule coverage receipt per exact ten-minute
// interval. A plan transition is serialized by ScheduleCoverageAuthority; a
// stale lifecycle instance fails closed rather than overwriting that plan.
func (l *ScheduleCoverageLifecycle) ProcessDue(now time.Time) error {
	interval := now.UTC().Truncate(scheduleInterval)
	l.mu.Lock()
	defer l.mu.Unlock()
	if interval.Equal(l.lastInterval) {
		return nil
	}
	plan, queue, err := BuildScheduleCoveragePlan(l.manifest, l.receipt, interval, l.shardCount)
	if err != nil {
		return errors.New("schedule coverage lifecycle input is invalid")
	}
	authority, err := OpenScheduleCoverageAuthority(l.statePath, plan, queue)
	if errors.Is(err, ErrSchedulePlanTransition) {
		authority, err = LoadScheduleCoverageAuthority(l.statePath)
		if err == nil {
			err = authority.Rebalance(plan, queue, interval)
		}
	}
	if err != nil {
		return err
	}
	if _, err := authority.RecordCoverage(interval); err != nil {
		return err
	}
	l.lastInterval = interval
	return nil
}
