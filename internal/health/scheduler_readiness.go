package health

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const schedulerLoopMaxAge = 5 * time.Second

type CanaryProgress struct {
	OperationID        string     `json:"operation_id"`
	LastStarted        *time.Time `json:"last_started,omitempty"`
	LastAccepted       *time.Time `json:"last_accepted,omitempty"`
	LastDelivered      *time.Time `json:"last_delivered,omitempty"`
	OriginalObservedAt *time.Time `json:"original_observed_at,omitempty"`
	State              string     `json:"state"`
	Reason             string     `json:"reason"`
}

type SchedulerReadiness struct {
	SchemaVersion      string           `json:"schema_version"`
	Ready              bool             `json:"ready"`
	State              string           `json:"state"`
	Reason             string           `json:"reason"`
	LastLoop           *time.Time       `json:"last_loop,omitempty"`
	StateFailures      uint64           `json:"state_failures"`
	Canaries           []CanaryProgress `json:"canaries"`
	PublicReadback     string           `json:"public_readback"`
	DeploymentIdentity string           `json:"deployment_identity"`
}

// Readiness is local progress evidence, deliberately distinct from immutable
// deployment acceptance and an independent public readback observer.
func (s *Scheduler) Readiness(now time.Time) SchedulerReadiness {
	s.mu.Lock()
	defer s.mu.Unlock()
	report := SchedulerReadiness{SchemaVersion: "datapan.health-self-readiness.v1", Ready: true, State: "ready", Reason: "pipeline_current", Canaries: make([]CanaryProgress, 0, len(s.config.Canaries)), PublicReadback: "not_checked", DeploymentIdentity: "not_checked", StateFailures: s.stateFailures}
	if !s.lastLoop.IsZero() {
		t := s.lastLoop
		report.LastLoop = &t
	}
	for _, canary := range s.config.Canaries {
		p := s.progress[canary.OperationID]
		p.OperationID = canary.OperationID
		if p.State == "" {
			p.State = "startup"
			p.Reason = "awaiting_first_delivery"
		}
		if p.LastDelivered != nil && now.Sub(*p.LastDelivered) > time.Duration(canary.HeartbeatMinutes)*time.Minute {
			p.State = "degraded"
			p.Reason = "delivery_stale"
		}
		if p.State != "ready" {
			report.Ready = false
			report.State = p.State
			report.Reason = p.Reason
		}
		report.Canaries = append(report.Canaries, p)
	}
	if s.lastLoop.IsZero() {
		report.Ready = false
		report.State = "startup"
		report.Reason = "awaiting_first_loop"
	} else if now.Sub(s.lastLoop) > schedulerLoopMaxAge || s.lastLoop.After(now.Add(receiptClockSkew)) {
		report.Ready = false
		report.State = "degraded"
		report.Reason = "scheduler_loop_stale"
	}
	if s.loopFailure {
		report.Ready = false
		report.State = "degraded"
		report.Reason = "scheduler_state_unavailable"
	}
	return report
}

func (s *Scheduler) recordProgress(id, phase, reason string, observed time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.progress[id]
	p.OperationID = id
	now := time.Now().UTC()
	switch phase {
	case "started":
		p.LastStarted = &now
	case "accepted":
		p.LastAccepted = &now
		p.OriginalObservedAt = &observed
	case "delivered":
		p.LastDelivered = &now
		p.State = "ready"
		p.Reason = "delivered"
	case "failed":
		p.State = "degraded"
		p.Reason = reason
	}
	s.progress[id] = p
}

// CheckExecutable never runs the child or prints command/environment values.
func CheckExecutable(path string) bool {
	resolved, err := exec.LookPath(path)
	if err != nil {
		return false
	}
	info, err := os.Stat(resolved)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}

// CheckWriteBoundary probes the actual parent mount without appending any
// observation. An existing target must also be writable, without truncation.
func CheckWriteBoundary(path string) bool {
	root := filepath.Dir(path)
	if os.MkdirAll(root, 0750) != nil {
		return false
	}
	if info, err := os.Stat(path); err == nil {
		if !info.Mode().IsRegular() {
			return false
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return false
		}
		_ = f.Close()
	} else if !os.IsNotExist(err) {
		return false
	}
	f, err := os.CreateTemp(root, ".health-write-check-")
	if err != nil {
		return false
	}
	name := f.Name()
	defer os.Remove(name)
	_, writeErr := f.Write([]byte{0})
	syncErr := f.Sync()
	closeErr := f.Close()
	return writeErr == nil && syncErr == nil && closeErr == nil
}
