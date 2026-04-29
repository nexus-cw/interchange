package middleware

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecoverCatchesPanic(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	h := Recover(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Errorf("want JSON error body, got %q", rec.Body.String())
	}
}

func TestRecoverPassesThroughOk(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	h := Recover(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("passthrough broken: %d %q", rec.Code, rec.Body.String())
	}
}

func TestRateLimitBlocksAfterBurst(t *testing.T) {
	cfg := RateLimitConfig{
		Default:        RateRule{PerSecond: 0.0001, Burst: 2},
		IdleEvictAfter: time.Hour,
	}
	hits := 0
	h, shutdown := RateLimit(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer shutdown()

	statuses := make([]int, 5)
	for i := range statuses {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		h.ServeHTTP(rec, req)
		statuses[i] = rec.Code
	}
	// First 2 should pass (burst), remaining should rate-limit.
	if statuses[0] != http.StatusOK || statuses[1] != http.StatusOK {
		t.Errorf("burst should pass: %v", statuses)
	}
	for i := 2; i < 5; i++ {
		if statuses[i] != http.StatusTooManyRequests {
			t.Errorf("after-burst should 429: pos=%d statuses=%v", i, statuses)
		}
	}
	if hits != 2 {
		t.Errorf("handler invoked %d times, want 2", hits)
	}
}

func TestRateLimitPerIPIsolated(t *testing.T) {
	cfg := RateLimitConfig{
		Default:        RateRule{PerSecond: 0.0001, Burst: 1},
		IdleEvictAfter: time.Hour,
	}
	h, shutdown := RateLimit(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer shutdown()

	hit := func(ip string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = ip
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// IP A: burst exhausted on first call, blocked on second.
	if got := hit("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("A first call: got %d", got)
	}
	if got := hit("1.1.1.1:1"); got != http.StatusTooManyRequests {
		t.Errorf("A second call: got %d", got)
	}
	// IP B: independent bucket, first call passes.
	if got := hit("2.2.2.2:1"); got != http.StatusOK {
		t.Errorf("B first call: got %d", got)
	}
}

func TestRateLimitRoutesMatchByPrefixAndMethod(t *testing.T) {
	cfg := RateLimitConfig{
		Default: RateRule{PerSecond: 100, Burst: 100},
		Routes: []RouteRule{
			{Method: http.MethodPost, Prefix: "/pair/request",
				Rule: RateRule{PerSecond: 0.0001, Burst: 1}},
		},
		IdleEvictAfter: time.Hour,
	}
	h, shutdown := RateLimit(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer shutdown()

	hit := func(method, path string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "9.9.9.9:1"
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// /pair/request POST: tight rule, second call should be blocked.
	if got := hit(http.MethodPost, "/pair/request"); got != http.StatusOK {
		t.Errorf("first POST: got %d", got)
	}
	if got := hit(http.MethodPost, "/pair/request"); got != http.StatusTooManyRequests {
		t.Errorf("second POST should 429: got %d", got)
	}
	// GET /pair/request falls through to default — same IP, generous rule.
	if got := hit(http.MethodGet, "/pair/request"); got != http.StatusOK {
		t.Errorf("GET should not match POST rule: got %d", got)
	}
	// Different prefix uses default — generous.
	for i := 0; i < 5; i++ {
		if got := hit(http.MethodPut, "/mailbox/foo"); got != http.StatusOK {
			t.Errorf("default rule call %d: got %d", i, got)
		}
	}
}

func TestRateLimitXForwardedForRespectedWhenTrusted(t *testing.T) {
	cfg := RateLimitConfig{
		Default:        RateRule{PerSecond: 0.0001, Burst: 1},
		IdleEvictAfter: time.Hour,
		TrustXFF:       true,
	}
	h, shutdown := RateLimit(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer shutdown()

	hit := func(xff string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "127.0.0.1:443" // Funnel proxy address (same for both clients)
		req.Header.Set("X-Forwarded-For", xff)
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := hit("8.8.8.8"); got != http.StatusOK {
		t.Errorf("client A first: %d", got)
	}
	if got := hit("8.8.8.8"); got != http.StatusTooManyRequests {
		t.Errorf("client A second: %d", got)
	}
	if got := hit("9.9.9.9"); got != http.StatusOK {
		t.Errorf("client B first should be independent: %d", got)
	}
}

func TestRateLimitXForwardedForIgnoredWhenUntrusted(t *testing.T) {
	cfg := RateLimitConfig{
		Default:        RateRule{PerSecond: 0.0001, Burst: 1},
		IdleEvictAfter: time.Hour,
		// TrustXFF: false (default) — public-port-direct deployments
		// where attackers could spoof XFF.
	}
	h, shutdown := RateLimit(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer shutdown()

	hit := func(xff string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "5.5.5.5:1234"
		req.Header.Set("X-Forwarded-For", xff)
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// Same RemoteAddr, different XFF — bucketed together because XFF
	// is ignored. Burst exhausts on first; second is 429 regardless of XFF.
	if got := hit("8.8.8.8"); got != http.StatusOK {
		t.Errorf("first call (XFF ignored): %d", got)
	}
	if got := hit("9.9.9.9"); got != http.StatusTooManyRequests {
		t.Errorf("XFF must not bypass bucket when untrusted: %d", got)
	}
}

func TestRateLimitMaxBucketsCapEnforced(t *testing.T) {
	cfg := RateLimitConfig{
		Default:           RateRule{PerSecond: 100, Burst: 100},
		IdleEvictAfter:    time.Hour,
		MaxBucketsPerRule: 3,
	}
	h, shutdown := RateLimit(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer shutdown()

	hit := func(ip string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = ip
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// Fill 3 buckets — all pass.
	for _, ip := range []string{"1.1.1.1:1", "2.2.2.2:1", "3.3.3.3:1"} {
		if got := hit(ip); got != http.StatusOK {
			t.Errorf("bucket fill %s: %d", ip, got)
		}
	}
	// 4th unique IP should hit the cap and 429 regardless of available rate.
	if got := hit("4.4.4.4:1"); got != http.StatusTooManyRequests {
		t.Errorf("4th IP must be capped: %d", got)
	}
	// Existing IP still allowed (it's already in the map).
	if got := hit("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("existing IP must continue: %d", got)
	}
}

func TestRateLimitConcurrentSafe(t *testing.T) {
	cfg := RateLimitConfig{
		Default:        RateRule{PerSecond: 1000, Burst: 1000},
		IdleEvictAfter: time.Hour,
	}
	h, shutdown := RateLimit(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer shutdown()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.RemoteAddr = "1.2.3.4:1"
			h.ServeHTTP(rec, req)
		}()
	}
	wg.Wait()
	// No assertion beyond "didn't deadlock or race-detector-fire". Run
	// `go test -race` to validate.
}
