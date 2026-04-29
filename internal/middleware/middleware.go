// Package middleware provides hardening wrappers for the interchange's
// HTTP handlers. Two concerns:
//
//   - Recover: catches panics in any handler so a single malformed
//     request can't crash the process and take both listeners with it.
//
//   - RateLimit: per-IP token bucket. The interchange is Funnel-exposed,
//     so an unauthenticated attacker can otherwise spam /pair/request or
//     /mailbox/:pathId PUT to fill disk. The bucket is keyed on the
//     X-Forwarded-For client (Tailscale Funnel sets this) with fallback
//     to RemoteAddr for tailnet-direct traffic.
//
// Both are mounted in cmd/interchange/main.go around the public mux.
// The tailnet mux is owner-only and bound to a private interface, so
// it gets Recover but no rate limit (operator traffic is trusted).
package middleware

import (
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Recover wraps next so that any panic produces a 500 response and a
// log line, instead of crashing the process. The stack is logged for
// debugging; clients see only a generic error.
func Recover(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Printf("panic in handler %s %s: %v\n%s",
					r.Method, r.URL.Path, rec, debug.Stack())
				// Best-effort: if headers already flushed there's
				// nothing to write; just swallow.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RateLimitConfig holds per-route limits. Routes match by URL prefix.
type RateLimitConfig struct {
	// Default applies when no route prefix matches.
	Default RateRule
	// Routes is a list of (prefix, rule) pairs evaluated in order.
	Routes []RouteRule
	// IdleEvictAfter is how long an unused per-IP bucket lingers
	// before the cleanup goroutine evicts it. Defaults to 10m.
	IdleEvictAfter time.Duration
	// MaxBucketsPerRule caps how many distinct IP buckets a single
	// rule can hold. Once reached, new IPs receive 429 immediately
	// (without consuming a token from any other bucket). Bounds
	// memory and prevents an attacker driving 10M unique IPs from
	// inflating the per-rule map. Defaults to 50_000.
	MaxBucketsPerRule int
	// TrustXFF, when true, reads the X-Forwarded-For header to key the
	// per-IP bucket. Set this ONLY when the public listener is
	// guaranteed to receive traffic via a trusted reverse proxy
	// (e.g. Tailscale Funnel) that overwrites XFF. Otherwise leave
	// false — an attacker on a directly-reachable port can spoof XFF
	// to bypass per-IP isolation. Defaults to false.
	TrustXFF bool
	Logger   *log.Logger
}

// RateRule is the token-bucket parameters for one route family.
// Burst is the max tokens; PerSecond is the refill rate.
type RateRule struct {
	PerSecond float64
	Burst     int
}

// RouteRule maps a URL-path prefix to a rate rule. The first matching
// prefix in the config wins. Method is checked too (empty = any).
type RouteRule struct {
	Method string
	Prefix string
	Rule   RateRule
}

type bucket struct {
	limiter *rate.Limiter
	last    time.Time
}

type rateLimiter struct {
	cfg    RateLimitConfig
	mu     sync.Mutex
	keyMap map[string]map[string]*bucket // key=ruleID, then ip
	stop   chan struct{}
}

// RateLimit returns middleware that token-bucket-throttles per (rule,
// client-IP). Rules are matched by URL prefix. Callers SHOULD call the
// returned shutdown to stop the eviction goroutine on server shutdown.
func RateLimit(cfg RateLimitConfig, next http.Handler) (http.Handler, func()) {
	if cfg.IdleEvictAfter == 0 {
		cfg.IdleEvictAfter = 10 * time.Minute
	}
	if cfg.MaxBucketsPerRule == 0 {
		cfg.MaxBucketsPerRule = 50_000
	}
	rl := &rateLimiter{
		cfg:    cfg,
		keyMap: map[string]map[string]*bucket{},
		stop:   make(chan struct{}),
	}
	go rl.evictLoop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rule, ruleID := rl.matchRule(r)
		ip := clientIP(r, cfg.TrustXFF)
		if !rl.allow(ruleID, ip, rule) {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
	return handler, func() { close(rl.stop) }
}

func (rl *rateLimiter) matchRule(r *http.Request) (RateRule, string) {
	for _, rr := range rl.cfg.Routes {
		if rr.Method != "" && rr.Method != r.Method {
			continue
		}
		if strings.HasPrefix(r.URL.Path, rr.Prefix) {
			return rr.Rule, rr.Method + ":" + rr.Prefix
		}
	}
	return rl.cfg.Default, "default"
}

func (rl *rateLimiter) allow(ruleID, ip string, rule RateRule) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	bucketsForRule, ok := rl.keyMap[ruleID]
	if !ok {
		bucketsForRule = map[string]*bucket{}
		rl.keyMap[ruleID] = bucketsForRule
	}
	b, ok := bucketsForRule[ip]
	if !ok {
		// Cap per-rule bucket cardinality. Above the cap, treat new
		// IPs as rate-limited rather than allocate. This bounds memory
		// (~50k buckets × small constant) and prevents a 10M-unique-IP
		// flood from blowing up the map and the eviction lock window.
		if len(bucketsForRule) >= rl.cfg.MaxBucketsPerRule {
			return false
		}
		b = &bucket{
			limiter: rate.NewLimiter(rate.Limit(rule.PerSecond), rule.Burst),
		}
		bucketsForRule[ip] = b
	}
	b.last = time.Now()
	return b.limiter.Allow()
}

func (rl *rateLimiter) evictLoop() {
	t := time.NewTicker(rl.cfg.IdleEvictAfter / 2)
	defer t.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case now := <-t.C:
			rl.mu.Lock()
			for ruleID, ips := range rl.keyMap {
				for ip, b := range ips {
					if now.Sub(b.last) > rl.cfg.IdleEvictAfter {
						delete(ips, ip)
					}
				}
				if len(ips) == 0 {
					delete(rl.keyMap, ruleID)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// clientIP returns the per-IP bucket key. When trustXFF is true and the
// X-Forwarded-For header is set, returns the first hop (the original
// client behind the trusted proxy). Otherwise returns the RemoteAddr
// host portion. trustXFF MUST be false unless the listener is
// guaranteed to be reached only via a proxy that overwrites XFF — an
// attacker on a directly-reachable port can spoof XFF and defeat
// per-IP isolation.
func clientIP(r *http.Request, trustXFF bool) string {
	if trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if comma := strings.IndexByte(xff, ','); comma > 0 {
				return strings.TrimSpace(xff[:comma])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
