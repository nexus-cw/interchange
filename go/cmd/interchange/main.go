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

	"github.com/nexus-cw/interchange/internal/discovery"
	"github.com/nexus-cw/interchange/internal/mailbox"
	"github.com/nexus-cw/interchange/internal/storage"
)

func main() {
	var (
		addr          = flag.String("addr", ":8443", "HTTP listen address for public endpoints")
		interchangeID = flag.String("id", "", "interchange_id — the nexus_id of the owner operator's Frame")
		dbPath        = flag.String("db", "interchange.db", "SQLite database path (use :memory: for in-memory)")
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

	logger.Printf("listening on %s (interchange_id=%s, db=%s)", *addr, *interchangeID, *dbPath)
	logger.Printf("WARNING: StubVerifier installed — signature verification not yet real (Part 2.5 pending)")
	if err := http.ListenAndServe(*addr, mux); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}
