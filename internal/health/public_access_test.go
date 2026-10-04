package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicReadGuardBoundsTrafficAndIgnoresForwardedIdentity(t *testing.T) {
	var calls int
	h, err := NewPublicReadGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }), PublicReadLimits{RequestsPerSecond: 2, Burst: 2, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	h.now = func() time.Time { return now }
	h.updated = now
	for i, code := range []int{200, 200, 429} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/datapan/v1/dependencies", nil)
		r.Header.Set("X-Forwarded-For", string(rune('a'+i)))
		h.ServeHTTP(w, r)
		if w.Code != code {
			t.Fatal("rate budget bypass")
		}
		if code == 429 && (w.Header().Get("Retry-After") != "1" || w.Header().Get("Cache-Control") != "no-store") {
			t.Fatal("retry contract missing")
		}
	}
	now = now.Add(time.Second)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || calls != 3 {
		t.Fatal("request budget did not recover")
	}
}
func TestPublicReadGuardBoundsConcurrentWork(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	h, _ := NewPublicReadGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release; w.WriteHeader(200) }), PublicReadLimits{RequestsPerSecond: 20, Burst: 40, MaxConcurrent: 1})
	done := make(chan struct{})
	go func() { h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)); close(done) }()
	<-started
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatal("concurrency limit missing")
	}
	close(release)
	<-done
}

type countingPublicSource struct {
	calls    atomic.Int32
	release  chan struct{}
	document PublicStatusDocument
	fail     atomic.Bool
}

func (s *countingPublicSource) Snapshot(ctx context.Context) (PublicStatusDocument, error) {
	s.calls.Add(1)
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return PublicStatusDocument{}, ctx.Err()
		}
	}
	if s.fail.Load() {
		return PublicStatusDocument{}, errors.New("secret provider detail")
	}
	return s.document, nil
}
func TestPublicCacheCoalescesReadsAndSurvivesViewerCancellation(t *testing.T) {
	source := &countingPublicSource{release: make(chan struct{}), document: testPublicDocument(t)}
	cached, _ := NewCachedPublicStatusSource(source, 5*time.Second, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := cached.Snapshot(ctx); first <- err }()
	deadline := time.Now().Add(time.Second)
	for source.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if !errors.Is(<-first, context.Canceled) {
		t.Fatal("viewer cancellation not honored")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doc, err := cached.Snapshot(context.Background())
			if err == nil && !doc.GeneratedAt.Equal(publicNow) {
				err = errors.New("original snapshot time changed")
			}
			errs <- err
		}()
	}
	close(source.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if source.calls.Load() != 1 {
		t.Fatal("readers amplified upstream work")
	}
}
func TestPublicCacheFailsClosedThenRecovers(t *testing.T) {
	source := &countingPublicSource{document: testPublicDocument(t)}
	cached, _ := NewCachedPublicStatusSource(source, 5*time.Second, time.Second)
	now := time.Now()
	cached.now = func() time.Time { return now }
	if _, err := cached.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	source.fail.Store(true)
	now = now.Add(6 * time.Second)
	if doc, err := cached.Snapshot(context.Background()); err == nil || !doc.GeneratedAt.IsZero() || err.Error() != "public status source unavailable" {
		t.Fatal("old healthy data or unsafe error substituted for failed refresh")
	}
	if _, err := cached.Snapshot(context.Background()); err == nil || source.calls.Load() != 2 {
		t.Fatal("outage retry not bounded")
	}
	source.fail.Store(false)
	now = now.Add(2 * time.Second)
	if _, err := cached.Snapshot(context.Background()); err != nil || source.calls.Load() != 3 {
		t.Fatal("source recovery not observed")
	}
}
func TestPublicCacheBoundsRefreshTimeout(t *testing.T) {
	source := &countingPublicSource{release: make(chan struct{})}
	cached, _ := NewCachedPublicStatusSource(source, time.Second, 10*time.Millisecond)
	if _, err := cached.Snapshot(context.Background()); err == nil {
		t.Fatal("refresh ignored timeout")
	}
}

func TestPublicReadRejectionPreservesAllowedCORSAndReadOnlyRoutes(t *testing.T) {
	source := &countingPublicSource{document: testPublicDocument(t)}
	cached, _ := NewCachedPublicStatusSource(source, 5*time.Second, time.Second)
	handler, _ := NewPublicStatusHandler(cached, []string{"https://datapan.statpan.com"})
	guard, _ := NewPublicReadGuard(handler, PublicReadLimits{RequestsPerSecond: 1, Burst: 1, MaxConcurrent: 1})
	guard.now = func() time.Time { return guard.updated }
	for _, code := range []int{200, 429} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/datapan/v1/dependencies", nil)
		r.Header.Set("Origin", "https://datapan.statpan.com")
		guard.ServeHTTP(w, r)
		if w.Code != code || w.Header().Get("Access-Control-Allow-Origin") != "https://datapan.statpan.com" {
			t.Fatal("allowed origin lost rejection visibility")
		}
	}
	for _, request := range []struct {
		method, path string
		code         int
	}{{"POST", "/datapan/v1/dependencies", 405}, {"GET", "/datapan/v1/dependencies?operation=any", 404}} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(request.method, request.path, nil))
		if w.Code != request.code {
			t.Fatal("execution request not rejected")
		}
	}
	if source.calls.Load() != 1 {
		t.Fatal("forbidden request reached upstream")
	}
}
