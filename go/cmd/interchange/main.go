// Command interchange is the Nexus Frame-to-Frame relay service.
//
// v3 protocol: see docs/specs/2026-04-24-frame-to-frame-relay-spec-v3.md
// (in the agent-network repo).
//
// Routes wired at this commit:
//   GET /.well-known/nexus-interchange   — discovery (Part 2.1)
//   GET /health                           — liveness (trivial)
//
// Mailbox + pairing endpoints land in later parts. The scaffold here is
// intentionally minimal so the HTTP shape can be confirmed end-to-end
// before storage and crypto are plumbed in.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/nexus-cw/interchange/internal/discovery"
)

func main() {
	var (
		addr          = flag.String("addr", ":8443", "HTTP listen address for public endpoints")
		interchangeID = flag.String("id", "", "interchange_id — the nexus_id of the owner operator's Frame")
	)
	flag.Parse()

	if *interchangeID == "" {
		log.Fatal("interchange: -id is required (owner nexus_id)")
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

	logger := log.New(os.Stderr, "interchange ", log.LstdFlags|log.Lmsgprefix)
	logger.Printf("listening on %s (interchange_id=%s)", *addr, *interchangeID)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}
