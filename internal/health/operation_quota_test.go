package health

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
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
