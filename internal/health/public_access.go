package health

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// PublicReadLimits use one bounded process-wide budget. Forwarding headers and
// peer identities cannot expand it or allocate unbounded per-client state.
type PublicReadLimits struct {
	RequestsPerSecond int
	Burst             int
	MaxConcurrent     int
}
type PublicReadGuard struct {
	next    http.Handler
	limits  PublicReadLimits
	active  chan struct{}
	mu      sync.Mutex
	tokens  float64
	updated time.Time
	now     func() time.Time
}

func NewPublicReadGuard(next http.Handler, limits PublicReadLimits) (*PublicReadGuard, error) {
	if next == nil || limits.RequestsPerSecond < 1 || limits.RequestsPerSecond > 1000 || limits.Burst < 1 || limits.Burst > 2000 || limits.MaxConcurrent < 1 || limits.MaxConcurrent > 256 {
		return nil, errors.New("invalid public read limits")
	}
	now := time.Now()
	return &PublicReadGuard{next: next, limits: limits, active: make(chan struct{}, limits.MaxConcurrent), tokens: float64(limits.Burst), updated: now, now: time.Now}, nil
}
func (g *PublicReadGuard) admit() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	elapsed := now.Sub(g.updated).Seconds()
	if elapsed > 0 {
		g.tokens += elapsed * float64(g.limits.RequestsPerSecond)
		if g.tokens > float64(g.limits.Burst) {
			g.tokens = float64(g.limits.Burst)
		}
		g.updated = now
	}
	if g.tokens < 1 {
		return false
	}
	g.tokens--
	return true
}
func (g *PublicReadGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.admit() {
		g.reject(w, r, http.StatusTooManyRequests)
		return
	}
	select {
	case g.active <- struct{}{}:
		defer func() { <-g.active }()
	default:
		g.reject(w, r, http.StatusServiceUnavailable)
		return
	}
	g.next.ServeHTTP(w, r)
}

type publicRefresh struct {
	done     chan struct{}
	document PublicStatusDocument
	err      error
}

// CachedPublicStatusSource retains only one snapshot and at most one refresh.
// Original timestamps and generated_at are unchanged. Expired data is never
// substituted for a failed refresh. A short error cache bounds outage retries.
type CachedPublicStatusSource struct {
	source  PublicStatusSource
	ttl     time.Duration
	timeout time.Duration
	mu      sync.Mutex
	cached  *publicRefresh
	expires time.Time
	flight  *publicRefresh
	now     func() time.Time
}

func NewCachedPublicStatusSource(source PublicStatusSource, ttl, timeout time.Duration) (*CachedPublicStatusSource, error) {
	if source == nil || ttl <= 0 || ttl > 30*time.Second || timeout <= 0 || timeout > 10*time.Second {
		return nil, errors.New("invalid public snapshot cache")
	}
	return &CachedPublicStatusSource{source: source, ttl: ttl, timeout: timeout, now: time.Now}, nil
}
func (s *CachedPublicStatusSource) Snapshot(ctx context.Context) (PublicStatusDocument, error) {
	if ctx.Err() != nil {
		return PublicStatusDocument{}, ctx.Err()
	}
	s.mu.Lock()
	if s.cached != nil && s.now().Before(s.expires) {
		cached := s.cached
		s.mu.Unlock()
		return cached.document, cached.err
	}
	flight := s.flight
	if flight == nil {
		flight = &publicRefresh{done: make(chan struct{})}
		s.flight = flight
		// A cancelled viewer cannot cancel the shared refresh for other viewers.
		go s.refresh(flight)
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return PublicStatusDocument{}, ctx.Err()
	case <-flight.done:
		return flight.document, flight.err
	}
}
func (s *CachedPublicStatusSource) refresh(flight *publicRefresh) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	document, err := s.source.Snapshot(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	flight.document, flight.err = document, err
	ttl := s.ttl
	if err != nil {
		flight.document = PublicStatusDocument{}
		flight.err = errors.New("public status source unavailable")
		ttl = time.Second
	}
	s.cached = flight
	s.expires = s.now().Add(ttl)
	s.flight = nil
	close(flight.done)
}

func (g *PublicReadGuard) reject(w http.ResponseWriter, r *http.Request, code int) {
	w.Header().Set("Retry-After", "1")
	if handler, ok := g.next.(*PublicStatusHandler); ok && isDatapanJSONRoute(r.URL.Path) {
		mergeVary(w.Header(), "Origin")
		if origin := r.Header.Get("Origin"); handler.origins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Expose-Headers", "Retry-After")
		}
	}
	writePublicError(w, code)
}
