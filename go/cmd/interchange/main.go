// Command interchange is the Nexus Frame-to-Frame relay service.
//
// v3 protocol: see docs/specs/2026-04-24-frame-to-frame-relay-spec-v3.md
// (in the agent-network repo).
//
// Routes wired at this commit:
//   GET  /.well-known/nexus-interchange   — discovery (Part 2.1)
//   GET  /health                           — liveness (trivial)
//   PUT  /mailbox/:pathId                  — append envelope (Part 2.3)
//   GET  /mailbox/:pathId?since=<msg_id>   — pull envelopes (Part 2.3)
//   POST /mailbox/:pathId/ack              — evict acked (Part 2.3)
//
// Pairing endpoints + real signature verification land in later parts.
// At this commit, the mailbox handlers install mailbox.StubVerifier,
// which fails closed — every request 401s until Part 2.5 wires real
// Ed25519/P-256 verification.
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

	"github.com/nexus-cw/interchange/internal/discovery"
	"github.com/nexus-cw/interchange/internal/mailbox"
	"github.com/nexus-cw/interchange/internal/storage"
	"github.com/nexus-cw/interchange/internal/sweep"
)

func main() {
	var (
		addr            = flag.String("addr", ":8443", "HTTP listen address for public endpoints")
		interchangeID   = flag.String("id", "", "interchange_id — the nexus_id of the owner operator's Frame")
		dbPath          = flag.String("db", "interchange.db", "SQLite database path (use :memory: for in-memory)")
		sweepInterval   = flag.Duration("sweep-interval", time.Hour, "retention sweep cadence")
		envelopeMaxAge  = flag.Duration("envelope-max-age", 7*24*time.Hour, "envelope retention age; older rows evicted on sweep")
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
		Verifier: mailbox.StubVerifier{}, // fail-closed placeholder; Part 2.5 swaps real crypto in
	}

	mux := http.NewServeMux()
	mux.HandleFunc(discovery.Path, discovery.Handler(*interchangeID))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/mailbox/", mb.Routes())

	// Sweeper runs in the background until ctx is cancelled by SIGINT/
	// SIGTERM. One goroutine handles both envelope eviction (7-day
	// retention) and pending-pair-request expiry (24h TTL).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sw := sweep.New(store, sweep.Config{
		Interval:       *sweepInterval,
		EnvelopeMaxAge: *envelopeMaxAge,
		Logger:         logger,
	})
	// Wait on the sweep goroutine before letting the deferred
	// store.Close() fire. If Close wins the race while Once() is
	// mid-query, the next storage call errors on a closed DB.
	var sweepWG sync.WaitGroup
	sweepWG.Add(1)
	go func() {
		defer sweepWG.Done()
		if err := sw.Run(ctx); err != nil {
			logger.Printf("sweep: %v", err)
		}
	}()

	logger.Printf("listening on %s (interchange_id=%s, db=%s, sweep=%s, envelope-max-age=%s)",
		*addr, *interchangeID, *dbPath, *sweepInterval, *envelopeMaxAge)
	logger.Printf("WARNING: StubVerifier installed — signature verification not yet real (Part 2.5 pending)")

	srv := &http.Server{Addr: *addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	logger.Printf("shutdown requested, draining HTTP...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	sweepWG.Wait()
	logger.Printf("shutdown complete")
}
