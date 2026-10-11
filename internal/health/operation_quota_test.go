package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestOperationQuotaAuthorityPersistsBudgetsAndFencesExpiredClaims(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	authority, err := OpenOperationQuotaAuthority(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy := operationQuotaTestPolicy(2, time.Minute, 0)
	first, err := authority.Acquire(policy, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now, 5*time.Second)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := authority.Acquire(policy, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(time.Second), 5*time.Second); !errors.Is(err, ErrOperationQuotaExhausted) {
		t.Fatalf("active concurrency was not enforced: %v", err)
	}
	if err := authority.Release(first, now.Add(2*time.Second)); err != nil {
		t.Fatalf("release: %v", err)
	}
	second, err := authority.Acquire(policy, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(3*time.Second), 5*time.Second)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if err := authority.Release(second, now.Add(4*time.Second)); err != nil {
		t.Fatalf("second release: %v", err)
	}
	thirdID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	if _, err := authority.Acquire(policy, thirdID, now.Add(5*time.Second), 5*time.Second); !errors.Is(err, ErrOperationQuotaExhausted) {
		t.Fatalf("released leases refunded request allowance: %v", err)
	}
	reopened, err := OpenOperationQuotaAuthority(authority.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Acquire(policy, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", now.Add(time.Minute), 5*time.Second); err != nil {
		t.Fatalf("window did not reset persisted allowance: %v", err)
	}
}

func TestOperationQuotaAuthorityEnforcesMinimumIntervalAndMonotonicTime(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	authority, err := OpenOperationQuotaAuthority(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy := operationQuotaTestPolicy(4, time.Minute, 10*time.Second)
	first, err := authority.Acquire(policy, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Release(first, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Acquire(policy, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(9*time.Second), 5*time.Second); !errors.Is(err, ErrOperationQuotaExhausted) {
		t.Fatalf("minimum interval was not enforced: %v", err)
	}
	if _, err := authority.Acquire(policy, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(10*time.Second), 5*time.Second); err != nil {
		t.Fatalf("minimum interval boundary was rejected: %v", err)
	}
	if _, err := authority.Acquire(policy, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", now.Add(9*time.Second), 5*time.Second); !errors.Is(err, ErrOperationQuotaUnavailable) {
		t.Fatalf("clock regression was accepted: %v", err)
	}
}

func TestOperationQuotaLiveClockFollowsLockOrderAndRetainsBackwardClockGuard(t *testing.T) {
	base := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	policy := operationQuotaTestPolicy(4, time.Hour, 0)
	policy.MaxConcurrent = 4
	firstID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	secondID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	olderCallerTime := base.Add(time.Second)
	lockOwnerTime := base.Add(2 * time.Second)
	lockWaiterTime := base.Add(3 * time.Second)

	t.Run("pre-lock caller timestamp can lose the lock-order race", func(t *testing.T) {
		authority, err := OpenOperationQuotaAuthority(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		lock := lockOperationQuotaAuthorityForTest(t, authority)
		started := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			close(started)
			_, acquireErr := authority.AcquireManyContext(context.Background(), []OperationQuotaPolicy{policy}, firstID, olderCallerTime, time.Minute)
			result <- acquireErr
		}()
		<-started
		time.Sleep(40 * time.Millisecond)
		seedOperationQuotaStateUnderHeldLock(t, authority, policy, secondID, lockOwnerTime)
		unlockOperationQuotaAuthorityForTest(t, lock)
		if err := <-result; !errors.Is(err, ErrOperationQuotaUnavailable) {
			t.Fatalf("stale timestamp sampled before lock acquisition was accepted: %v", err)
		}
	})

	t.Run("live clock is sampled once after lock acquisition", func(t *testing.T) {
		authority, err := OpenOperationQuotaAuthority(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		lock := lockOperationQuotaAuthorityForTest(t, authority)
		started := make(chan struct{})
		clockCalled := make(chan struct{}, 1)
		clockCalls := 0
		result := make(chan struct {
			claims []OperationQuotaClaim
			at     time.Time
			err    error
		}, 1)
		go func() {
			close(started)
			claims, at, acquireErr := authority.acquireManyWithClockContext(context.Background(), []OperationQuotaPolicy{policy}, firstID, time.Minute, func() time.Time {
				clockCalls++
				select {
				case clockCalled <- struct{}{}:
				default:
				}
				return lockWaiterTime
			})
			result <- struct {
				claims []OperationQuotaClaim
				at     time.Time
				err    error
			}{claims: claims, at: at, err: acquireErr}
		}()
		<-started
		time.Sleep(40 * time.Millisecond)
		select {
		case <-clockCalled:
			t.Fatal("quota clock was sampled before the authority lock was acquired")
		default:
		}
		seedOperationQuotaStateUnderHeldLock(t, authority, policy, secondID, lockOwnerTime)
		unlockOperationQuotaAuthorityForTest(t, lock)
		acquired := <-result
		if acquired.err != nil || len(acquired.claims) != 1 || !acquired.at.Equal(lockWaiterTime) {
			t.Fatalf("lock-ordered quota reservation failed: claims=%d sampled_at=%s err=%v", len(acquired.claims), acquired.at, acquired.err)
		}
		if clockCalls != 1 {
			t.Fatalf("quota clock callback count=%d, want exactly one", clockCalls)
		}
	})

	t.Run("genuine under-lock clock rollback is still rejected", func(t *testing.T) {
		authority, err := OpenOperationQuotaAuthority(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		seedOperationQuotaStateUnderHeldLock(t, authority, policy, secondID, lockOwnerTime)
		_, _, err = authority.acquireManyWithClockContext(context.Background(), []OperationQuotaPolicy{policy}, firstID, time.Minute, func() time.Time {
			return olderCallerTime
		})
		if !errors.Is(err, ErrOperationQuotaUnavailable) {
			t.Fatalf("actual clock rollback under the authority lock was accepted: %v", err)
		}
	})
}

func TestOperationQuotaLiveReleaseFollowsLockOrderAndRetainsFencing(t *testing.T) {
	base := time.Date(2026, 10, 11, 13, 0, 0, 0, time.UTC)
	policy := operationQuotaTestPolicy(4, time.Hour, 0)
	policy.MaxConcurrent = 4
	firstID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	secondID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	olderReleaseTime := base.Add(time.Second)
	competingReserveTime := base.Add(2 * time.Second)
	liveReleaseTime := base.Add(3 * time.Second)

	t.Run("pre-lock release timestamp loses a reordered reservation", func(t *testing.T) {
		authority, err := OpenOperationQuotaAuthority(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		first, err := authority.Acquire(policy, firstID, base, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		lock := lockOperationQuotaAuthorityForTest(t, authority)
		started := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			close(started)
			result <- authority.ReleaseManyContext(context.Background(), []OperationQuotaClaim{first}, olderReleaseTime)
		}()
		<-started
		time.Sleep(40 * time.Millisecond)
		reserveOperationQuotaClaimUnderHeldLock(t, authority, policy, secondID, competingReserveTime, time.Minute)
		unlockOperationQuotaAuthorityForTest(t, lock)
		if err := <-result; !errors.Is(err, ErrOperationQuotaUnavailable) {
			t.Fatalf("stale release timestamp was accepted after a later reservation: %v", err)
		}
		state, found, err := readOperationQuotaState(authority.statePath(policy.ScopeSHA256))
		if err != nil || !found || state.RequestsUsed != 2 || len(state.Active) != 2 {
			t.Fatalf("rejected release changed either live claim or request budget: state=%#v found=%t err=%v", state, found, err)
		}
		if err := authority.Release(first, competingReserveTime.Add(time.Second)); err != nil {
			t.Fatalf("current original claim could not be released at lock-order time: %v", err)
		}
	})

	t.Run("live release samples once after lock and preserves other claims", func(t *testing.T) {
		authority, err := OpenOperationQuotaAuthority(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		first, err := authority.Acquire(policy, firstID, base, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		lock := lockOperationQuotaAuthorityForTest(t, authority)
		started := make(chan struct{})
		clockCalled := make(chan struct{}, 1)
		clockCalls := 0
		result := make(chan error, 1)
		go func() {
			close(started)
			result <- authority.releaseManyWithClockContext(context.Background(), []OperationQuotaClaim{first}, func() time.Time {
				clockCalls++
				select {
				case clockCalled <- struct{}{}:
				default:
				}
				return liveReleaseTime
			})
		}()
		<-started
		time.Sleep(40 * time.Millisecond)
		select {
		case <-clockCalled:
			t.Fatal("release clock was sampled before the authority lock was acquired")
		default:
		}
		second := reserveOperationQuotaClaimUnderHeldLock(t, authority, policy, secondID, competingReserveTime, time.Minute)
		unlockOperationQuotaAuthorityForTest(t, lock)
		if err := <-result; err != nil {
			t.Fatalf("live release failed after the later reservation: %v", err)
		}
		if clockCalls != 1 {
			t.Fatalf("release clock callback count=%d, want exactly one", clockCalls)
		}
		state, found, err := readOperationQuotaState(authority.statePath(policy.ScopeSHA256))
		if err != nil || !found || state.RequestsUsed != 2 || len(state.Active) != 1 || state.Active[secondID].Generation != second.Generation {
			t.Fatalf("release refunded budget or removed a competing lease: state=%#v found=%t err=%v", state, found, err)
		}
		if err := authority.releaseManyWithClockContext(context.Background(), []OperationQuotaClaim{second}, func() time.Time {
			return competingReserveTime
		}); !errors.Is(err, ErrOperationQuotaUnavailable) {
			t.Fatalf("genuine backward release clock was accepted: %v", err)
		}
		if err := authority.releaseManyWithClockContext(context.Background(), []OperationQuotaClaim{first}, func() time.Time {
			return liveReleaseTime.Add(time.Second)
		}); !errors.Is(err, ErrOperationQuotaFenced) {
			t.Fatalf("stale released claim was accepted: %v", err)
		}
		if err := authority.releaseManyWithClockContext(context.Background(), []OperationQuotaClaim{second}, func() time.Time {
			return second.ExpiresAt
		}); !errors.Is(err, ErrOperationQuotaFenced) {
			t.Fatalf("expired live claim was accepted: %v", err)
		}
	})
}

func lockOperationQuotaAuthorityForTest(t *testing.T, authority *OperationQuotaAuthority) *os.File {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(authority.root, ".authority.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	return file
}

func unlockOperationQuotaAuthorityForTest(t *testing.T, file *os.File) {
	t.Helper()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func seedOperationQuotaStateUnderHeldLock(t *testing.T, authority *OperationQuotaAuthority, policy OperationQuotaPolicy, attemptID string, at time.Time) OperationQuotaClaim {
	t.Helper()
	return reserveOperationQuotaClaimUnderHeldLock(t, authority, policy, attemptID, at, time.Minute)
}

func reserveOperationQuotaClaimUnderHeldLock(t *testing.T, authority *OperationQuotaAuthority, policy OperationQuotaPolicy, attemptID string, at time.Time, lease time.Duration) OperationQuotaClaim {
	t.Helper()
	state, found, err := readOperationQuotaState(authority.statePath(policy.ScopeSHA256))
	if err != nil {
		t.Fatal(err)
	}
	state, claim, err := nextOperationQuotaClaim(state, found, policy, attemptID, at, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOperationQuotaState(authority.statePath(policy.ScopeSHA256), state); err != nil {
		t.Fatal(err)
	}
	return claim
}

func TestOperationQuotaAuthorityRejectsStaleReleaseAndPolicyMutation(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	authority, err := OpenOperationQuotaAuthority(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy := operationQuotaTestPolicy(3, time.Minute, 0)
	first, err := authority.Acquire(policy, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mutated := policy
	mutated.RequestsPerWindow++
	if _, err := authority.Acquire(mutated, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(time.Second), 5*time.Second); !errors.Is(err, ErrOperationQuotaTransition) {
		t.Fatalf("mid-window policy mutation was accepted: %v", err)
	}
	second, err := authority.Acquire(policy, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(6*time.Second), 5*time.Second)
	if err != nil {
		t.Fatalf("expired lease did not release concurrency: %v", err)
	}
	if err := authority.Release(first, now.Add(7*time.Second)); !errors.Is(err, ErrOperationQuotaFenced) {
		t.Fatalf("stale token released a newer claim: %v", err)
	}
	if err := authority.Release(second, now.Add(8*time.Second)); err != nil {
		t.Fatalf("current token could not release: %v", err)
	}
	if _, err := authority.Acquire(mutated, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", now.Add(time.Minute), 5*time.Second); err != nil {
		t.Fatalf("policy change at next quota window was rejected: %v", err)
	}
}

func TestOperationQuotaWindowDrainSeparatesSamePolicyFromPolicyMutation(t *testing.T) {
	boundary := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	window := 10 * time.Minute
	policy := operationQuotaTestPolicy(10, window, 0)
	authority, err := OpenOperationQuotaAuthority(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldAttemptID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	first, err := authority.Acquire(policy, oldAttemptID, boundary.Add(-time.Second), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	before, found, err := readOperationQuotaState(authority.statePath(policy.ScopeSHA256))
	if err != nil || !found {
		t.Fatalf("read old-window quota state: found=%t err=%v", found, err)
	}

	_, err = authority.Acquire(policy, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", boundary.Add(time.Second), time.Minute)
	if !errors.Is(err, errOperationQuotaWindowDraining) || !errors.Is(err, ErrOperationQuotaTransition) {
		t.Fatalf("same-policy rollover with a live old lease did not report a retryable drain subtype: %v", err)
	}
	after, found, readErr := readOperationQuotaState(authority.statePath(policy.ScopeSHA256))
	if readErr != nil || !found || after.WindowStarted != before.WindowStarted || after.RequestsUsed != before.RequestsUsed || after.Generation != before.Generation || len(after.Active) != len(before.Active) {
		t.Fatalf("rejected rollover changed durable quota usage or claims: before=%#v after=%#v err=%v", before, after, readErr)
	}

	mutated := policy
	mutated.RequestsPerWindow++
	_, err = authority.Acquire(mutated, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", boundary.Add(2*time.Second), time.Minute)
	if !errors.Is(err, ErrOperationQuotaTransition) || errors.Is(err, errOperationQuotaWindowDraining) {
		t.Fatalf("policy mutation acquired the transient same-policy retry marker: %v", err)
	}

	if err := authority.Release(first, boundary.Add(3*time.Second)); err != nil {
		t.Fatalf("release old claim after the boundary: %v", err)
	}
	rolled, err := authority.Acquire(policy, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", boundary.Add(4*time.Second), time.Minute)
	if err != nil {
		t.Fatalf("empty old window did not roll over: %v", err)
	}
	state, found, err := readOperationQuotaState(authority.statePath(policy.ScopeSHA256))
	if err != nil || !found || !state.WindowStarted.Equal(boundary) || state.RequestsUsed != 1 || state.Active[rolled.AttemptID].Generation != rolled.Generation {
		t.Fatalf("ordinary window rollover did not start with one claimed request: state=%#v err=%v", state, err)
	}
}

func TestOperationQuotaWindowDrainIsAtomicAcrossScopes(t *testing.T) {
	boundary := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	authority, err := OpenOperationQuotaAuthority(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policies := []OperationQuotaPolicy{
		operationQuotaPolicyForScope("global", "window-drain-atomic", 4, 100),
		operationQuotaPolicyForScope("provider", "window-drain-atomic", 4, 100),
	}
	for index := range policies {
		policies[index].Window = 10 * time.Minute
	}
	normalized, err := normalizeOperationQuotaPolicies(policies)
	if err != nil {
		t.Fatal(err)
	}
	activePolicy := normalized[len(normalized)-1]
	if _, err := authority.Acquire(activePolicy, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", boundary.Add(-time.Second), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AcquireMany(normalized, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", boundary.Add(time.Second), time.Minute); !errors.Is(err, errOperationQuotaWindowDraining) {
		t.Fatalf("multi-scope acquisition did not identify the active old-window lease: %v", err)
	}
	if _, found, err := readOperationQuotaState(authority.statePath(normalized[0].ScopeSHA256)); err != nil || found {
		t.Fatalf("failed atomic acquisition persisted an earlier scope claim: found=%t err=%v", found, err)
	}
	state, found, err := readOperationQuotaState(authority.statePath(activePolicy.ScopeSHA256))
	if err != nil || !found || state.WindowStarted != boundary.Add(-time.Minute).Truncate(activePolicy.Window) || state.RequestsUsed != 1 || len(state.Active) != 1 {
		t.Fatalf("failed atomic acquisition changed the blocked scope: state=%#v err=%v", state, err)
	}
}

func TestOperationQuotaAuthorityCoordinatesIndependentWorkerProcesses(t *testing.T) {
	root := t.TempDir()
	left, err := OpenOperationQuotaAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	right, err := OpenOperationQuotaAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	policy := operationQuotaTestPolicy(1, time.Minute, 0)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	var successes int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			attemptID := fmt.Sprintf("%08x-0000-4000-8000-%012x", i+1, i+1)
			instance := left
			if i%2 != 0 {
				instance = right
			}
			if _, err := instance.Acquire(policy, attemptID, now, 10*time.Second); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			} else if !errors.Is(err, ErrOperationQuotaExhausted) {
				t.Errorf("unexpected claim error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("shared authority admitted %d concurrent claims, want 1", successes)
	}
}

func TestOperationQuotaAcquireManyCoordinatesSharedCredentialAcrossProcessesAndAPIs(t *testing.T) {
	root := t.TempDir()
	left, err := OpenOperationQuotaAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	right, err := OpenOperationQuotaAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	global := operationQuotaPolicyForScope("global", "datapan", 4, 10)
	provider := operationQuotaPolicyForScope("provider", "provider-a", 2, 10)
	sharedCredential := operationQuotaPolicyForScope("credential", "shared-credential-a", 1, 10)
	apiPolicies := [][]OperationQuotaPolicy{
		{global, provider, sharedCredential, operationQuotaPolicyForScope("api", "provider-a:api-one", 1, 5)},
		{global, provider, sharedCredential, operationQuotaPolicyForScope("api", "provider-a:api-two", 1, 5)},
	}
	instances := []*OperationQuotaAuthority{left, right}
	var successes int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range apiPolicies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			attemptID := fmt.Sprintf("%08x-0000-4000-8000-%012x", i+1, i+1)
			_, err := instances[i].AcquireMany(apiPolicies[i], attemptID, now, 10*time.Second)
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			} else if !errors.Is(err, ErrOperationQuotaExhausted) {
				t.Errorf("unexpected multi-scope reservation error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("shared credential bucket admitted %d APIs in parallel, want one", successes)
	}
}

func TestOperationQuotaAcquireManySharesHierarchicalScopesAndRollsBackRejectedReservation(t *testing.T) {
	authority, err := OpenOperationQuotaAuthority(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	global := operationQuotaPolicyForScope("global", "datapan", 2, 4)
	provider := operationQuotaPolicyForScope("provider", "provider-a", 1, 4)
	credential := operationQuotaPolicyForScope("credential", "shared-credential-a", 1, 4)
	apiOne := operationQuotaPolicyForScope("api", "provider-a:api-one", 1, 1)
	apiTwo := operationQuotaPolicyForScope("api", "provider-a:api-two", 1, 1)
	firstScopes := []OperationQuotaPolicy{global, provider, credential, apiOne}
	first, err := authority.AcquireMany(firstScopes, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now, 5*time.Second)
	if err != nil || len(first) != len(firstScopes) {
		t.Fatalf("first hierarchical reservation failed: claims=%d err=%v", len(first), err)
	}
	secondScopes := []OperationQuotaPolicy{global, provider, credential, apiTwo}
	if _, err := authority.AcquireMany(secondScopes, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(time.Second), 5*time.Second); !errors.Is(err, ErrOperationQuotaExhausted) {
		t.Fatalf("provider/shared-credential concurrency did not reject second API: %v", err)
	}
	if err := authority.ReleaseMany(first, now.Add(2*time.Second)); err != nil {
		t.Fatalf("release of all hierarchical scopes failed: %v", err)
	}
	second, err := authority.AcquireMany(secondScopes, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(3*time.Second), 5*time.Second)
	if err != nil || len(second) != len(secondScopes) {
		t.Fatalf("failed reservation partially consumed API-two budget: claims=%d err=%v", len(second), err)
	}
}

func TestOperationQuotaAcquireManyFencesAllScopesTogether(t *testing.T) {
	authority, err := OpenOperationQuotaAuthority(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	policies := []OperationQuotaPolicy{
		operationQuotaPolicyForScope("provider", "provider-a", 1, 3),
		operationQuotaPolicyForScope("credential", "shared-credential-a", 1, 3),
		operationQuotaPolicyForScope("api", "provider-a:api-one", 1, 3),
	}
	first, err := authority.AcquireMany(policies, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	second, err := authority.AcquireMany(policies, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(6*time.Second), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.ReleaseMany(first, now.Add(7*time.Second)); !errors.Is(err, ErrOperationQuotaFenced) {
		t.Fatalf("stale multi-scope token was accepted: %v", err)
	}
	for _, policy := range policies {
		state, found, err := readOperationQuotaState(authority.statePath(policy.ScopeSHA256))
		if err != nil || !found || state.Active[second[0].AttemptID].Generation == 0 {
			t.Fatalf("stale release changed scope %s: found=%t err=%v", policy.ScopeSHA256, found, err)
		}
	}
	if _, err := authority.AcquireMany(policies, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", now.Add(8*time.Second), 5*time.Second); !errors.Is(err, ErrOperationQuotaExhausted) {
		t.Fatalf("stale release freed at least one new scope: %v", err)
	}
	if err := authority.ReleaseMany(second, now.Add(9*time.Second)); err != nil {
		t.Fatalf("current multi-scope token could not release: %v", err)
	}
}

func TestOperationQuotaAcquireManyRecoversWriteAheadReservation(t *testing.T) {
	root := t.TempDir()
	authority, err := OpenOperationQuotaAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	policies := []OperationQuotaPolicy{
		operationQuotaPolicyForScope("provider", "provider-a", 1, 1),
		operationQuotaPolicyForScope("api", "provider-a:api-one", 1, 1),
	}
	attempt := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	states := make([]operationQuotaState, 0, len(policies))
	for _, policy := range policies {
		state, _, err := nextOperationQuotaClaim(operationQuotaState{}, false, policy, attempt, now, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, state)
	}
	transaction := operationQuotaTransaction{SchemaVersion: operationQuotaTransactionSchemaVersion, Kind: "reserve", AttemptID: attempt, States: states}
	if err := authority.writeOperationQuotaTransaction(transaction); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AcquireMany(policies, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", now.Add(time.Second), 5*time.Second); !errors.Is(err, ErrOperationQuotaExhausted) {
		t.Fatalf("pending reservation was not recovered before next caller: %v", err)
	}
	for _, policy := range policies {
		state, found, err := readOperationQuotaState(authority.statePath(policy.ScopeSHA256))
		if err != nil || !found || state.Active[attempt].Generation != 1 {
			t.Fatalf("scope %s did not recover complete reservation: found=%t err=%v", policy.ScopeSHA256, found, err)
		}
	}
}

func TestOperationQuotaScopeDigestSeparatesDimensions(t *testing.T) {
	input := []byte("datapan.quota-scope.v1\x00credential\x00shared-service-key-scope-1")
	expected := sha256.Sum256(input)
	first := OperationQuotaScopeDigest("credential", "shared-service-key-scope-1")
	if first != hex.EncodeToString(expected[:]) {
		t.Fatal("scope digest differs from the Registry canonical derivation")
	}
	if first == OperationQuotaScopeDigest("api", "shared-service-key-scope-1") || first == OperationQuotaScopeDigest("credential", "shared-service-key-scope-2") {
		t.Fatal("scope digest did not bind quota kind and opaque shared key")
	}
}

func TestOperationQuotaPolicyFromEvidenceFailsClosedAcrossIndependentAdmissionStates(t *testing.T) {
	scope := OperationQuotaScopeDigest("credential", "shared-service-key-scope")
	evidence := []OperationQuotaEvidenceRef{operationQuotaTestEvidence()}
	build := func(requestPlan, binding, admission, digest string, evidence []OperationQuotaEvidenceRef) (OperationQuotaPolicy, error) {
		return OperationQuotaPolicyFromEvidence(requestPlan, binding, admission, "credential", "shared-service-key-scope", digest, 1, 2, 60, 0, evidence)
	}
	policy, err := build("complete", "bound", "admitted", scope, evidence)
	if err != nil || policy.ScopeSHA256 != scope {
		t.Fatalf("evidence-backed admission was rejected: policy=%+v err=%v", policy, err)
	}
	for name, test := range map[string]struct {
		requestPlan string
		binding     string
		admission   string
		digest      string
		evidence    []OperationQuotaEvidenceRef
	}{
		"unresolved request": {"unresolved", "bound", "admitted", scope, evidence},
		"unbound runtime":    {"complete", "unbound", "admitted", scope, evidence},
		"not admitted":       {"complete", "bound", "not_admitted", scope, evidence},
		"missing evidence":   {"complete", "bound", "admitted", scope, nil},
		"scope mismatch":     {"complete", "bound", "admitted", OperationQuotaScopeDigest("credential", "other-shared-scope"), evidence},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := build(test.requestPlan, test.binding, test.admission, test.digest, test.evidence); err == nil {
				t.Fatal("unsafe quota plan was accepted")
			}
		})
	}
}

func operationQuotaTestPolicy(requests int, window time.Duration, minimumInterval time.Duration) OperationQuotaPolicy {
	policy := operationQuotaPolicyForScope("api", "provider-a:api-1", 1, requests)
	policy.Window = window
	policy.MinimumInterval = minimumInterval
	return policy
}

func operationQuotaPolicyForScope(kind, key string, concurrency, requests int) OperationQuotaPolicy {
	return OperationQuotaPolicy{
		ScopeSHA256:       OperationQuotaScopeDigest(kind, key),
		MaxConcurrent:     concurrency,
		RequestsPerWindow: requests,
		Window:            time.Minute,
	}
}

func operationQuotaTestEvidence() OperationQuotaEvidenceRef {
	return OperationQuotaEvidenceRef{
		ArtifactPath: "policy/runtime-quotas.json",
		SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		JSONPointer:  "#/scopes/0",
		EvidenceKind: "reviewed_policy",
	}
}
