// Command interchange is the Nexus Frame-to-Frame relay service.
//
// v3 protocol: see docs/specs/2026-04-24-frame-to-frame-relay-spec-v3.md
// (in the agent-network repo).
//
// Two listeners:
//
//   PUBLIC  (-addr, default :8443, Funnel-exposed in production):
//     GET  /.well-known/nexus-interchange   — discovery
//     GET  /health                           — liveness
//     PUT  /mailbox/:pathId                  — append envelope
//     GET  /mailbox/:pathId?since=<msg_id>   — pull envelopes
//     POST /mailbox/:pathId/ack              — evict acked
//     POST /pair/request                     — requester initiates pair
//     GET  /pair/requests/:id                — requester polls status
//
//   TAILNET (-tailnet-addr, Tailscale-bound in production):
//     GET  /pair/requests?status=pending     — owner lists pending
//     POST /pair/requests/:id/approve        — owner approves
//     POST /pair/requests/:id/deny           — owner denies
//
// The tailnet/public split is the primary control enforcing the
// "operator approves" invariant. The PUBLIC listener has no way to
// reach approve/deny at all. An optional shared-secret check layers
// on top of the network binding via -owner-secret.
//
// Signature verification uses internal/crypto.EdVerifier (Ed25519 only
// at v1 per anvil #7828/#7841). Retention sweep runs hourly; pair
// requests TTL-expire after 24h.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nexus-cw/interchange/internal/crypto"
	"github.com/nexus-cw/interchange/internal/discovery"
	"github.com/nexus-cw/interchange/internal/mailbox"
	"github.com/nexus-cw/interchange/internal/pairflow"
	"github.com/nexus-cw/interchange/internal/storage"
	"github.com/nexus-cw/interchange/internal/sweep"
)

func main() {
	var (
		addr           = flag.String("addr", ":8443", "public HTTP listen address (Funnel-exposed)")
		tailnetAddr    = flag.String("tailnet-addr", "127.0.0.1:8444", "tailnet-bound listen address for owner endpoints (approve/deny/list). In production bind to tailscale0.")
		interchangeID  = flag.String("id", "", "interchange_id — the nexus_id of the owner operator's Frame")
		dbPath         = flag.String("db", "interchange.db", "SQLite database path (use :memory: for in-memory)")
		sweepInterval  = flag.Duration("sweep-interval", time.Hour, "retention sweep cadence")
		envelopeMaxAge = flag.Duration("envelope-max-age", 7*24*time.Hour, "envelope retention age; older rows evicted on sweep")
		ownerSecret    = flag.String("owner-secret", "", "optional shared secret required on owner (tailnet) endpoints — layers on top of tailnet binding. Empty = no header check.")
	)
	flag.Parse()

	if *interchangeID == "" {
		log.Fatal("interchange: -id is required (owner nexus_id)")
	}

	logger := log.New(os.Stderr, "interchange ", log.LstdFlags|log.Lmsgprefix)

	store, err := storage.OpenSQLite(*dbPath)
	if err != nil {
		logger.Fatalf("open storage: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.CreateSchema(context.Background()); err != nil {
		logger.Fatalf("create schema: %v", err)
	}

	mb := &mailbox.Handler{
		Store:    store,
		Verifier: crypto.EdVerifier{},
	}
	pf := &pairflow.Handler{
		Store:       store,
		OwnerSecret: *ownerSecret,
	}

	// Public mux — everything Funnel-reachable.
	publicMux := http.NewServeMux()
	publicMux.HandleFunc(discovery.Path, discovery.Handler(*interchangeID))
	publicMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	publicMux.Handle("/mailbox/", mb.Routes())
	publicMux.Handle("/pair/", pf.PublicRoutes())

	// Tailnet mux — owner-only endpoints. Served on a separate listener
	// so the network binding (not header auth) is the primary control.
	tailnetMux := http.NewServeMux()
	tailnetMux.Handle("/pair/", pf.OwnerRoutes())
	tailnetMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Signal-cancelled context propagates to sweep + shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Retention sweep.
	sw := sweep.New(store, sweep.Config{
		Interval:       *sweepInterval,
		EnvelopeMaxAge: *envelopeMaxAge,
		Logger:         logger,
	})
	var sweepWG sync.WaitGroup
	sweepWG.Add(1)
	go func() {
		defer sweepWG.Done()
		if err := sw.Run(ctx); err != nil {
			logger.Printf("sweep: %v", err)
		}
	}()

	logger.Printf("public listener on %s", *addr)
	logger.Printf("tailnet listener on %s (owner endpoints — bind to tailscale0 in production)", *tailnetAddr)
	logger.Printf("interchange_id=%s db=%s sweep=%s envelope-max-age=%s", *interchangeID, *dbPath, *sweepInterval, *envelopeMaxAge)
	logger.Printf("signature verification: Ed25519 via internal/crypto")
	if *ownerSecret != "" {
		logger.Printf("owner endpoints: X-Owner-Secret header required (layered on tailnet binding)")
	} else {
		logger.Printf("owner endpoints: tailnet binding only — no shared secret configured")
	}

	publicSrv := &http.Server{Addr: *addr, Handler: publicMux}
	tailnetSrv := &http.Server{Addr: *tailnetAddr, Handler: tailnetMux}

	go func() {
		if err := publicSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("public serve: %v", err)
		}
	}()
	go func() {
		if err := tailnetSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("tailnet serve: %v", err)
		}
	}()

	<-ctx.Done()
	logger.Printf("shutdown requested, draining HTTP...")
	// Each server gets its own 10s drain window — sharing a single
	// timeout would let a slow public drain consume the entire budget
	// and abandon tailnet requests without a chance to complete.
	pubCtx, pubCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pubCancel()
	_ = publicSrv.Shutdown(pubCtx)

	tailCtx, tailCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer tailCancel()
	_ = tailnetSrv.Shutdown(tailCtx)

	sweepWG.Wait()
	logger.Printf("shutdown complete")
}
