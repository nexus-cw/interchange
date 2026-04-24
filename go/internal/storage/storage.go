// Package storage defines the persistence contract for the interchange
// and provides the SQLite adapter used on dMon.
//
// The Storage interface is deliberately narrow — just the operations the
// HTTP handlers actually need — so a future CF/D1 adapter can reimplement
// against it without reshaping the request handlers.
//
// Schema is frozen by the v3 spec §Storage. Migrations live in
// interchange/migrations/ on the TS side; the Go adapter re-creates the
// same shape via CreateSchema so a fresh SQLite file is usable without
// external migration tooling.
package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by lookups when no row matches. Distinct from
// a SQL-level error so handlers can map it to 404 without leaking driver
// internals.
var ErrNotFound = errors.New("storage: not found")

// ErrDuplicate is returned by inserts when a primary-key conflict fires.
// Used on the PUT /mailbox path to translate to 409.
var ErrDuplicate = errors.New("storage: duplicate key")

// ErrConflict is returned by UpdatePairRequestStatus when a transition
// would cross between distinct terminal states (e.g. deny-after-approve).
// Handlers map this to 409.
var ErrConflict = errors.New("storage: status conflict")

// Envelope is a stored outer envelope — ciphertext + signature +
// routing metadata. Frames PUT these; the interchange persists them
// until the recipient acks or the retention sweep fires.
type Envelope struct {
	MsgID      string
	PathID     string
	Direction  Direction
	ReceivedAt time.Time
	Ciphertext string // base64url
	Signature  string // base64url detached signature (X-Nexus-Signature)
	OuterJSON  string // canonical JSON of the outer envelope, as received
}

// Direction indicates which half of a pair an envelope is addressed to.
// Read direction is determined by "sender sent it, so it's addressed to
// the other side" — the interchange never needs to resolve nexus_id at
// query time.
type Direction string

const (
	AToB Direction = "A_to_B"
	BToA Direction = "B_to_A"
)

// PairRequestStatus tracks lifecycle: pending (awaiting owner decision),
// approved (pair activated, pathId assigned), denied (owner rejected),
// expired (TTL elapsed without decision).
type PairRequestStatus string

const (
	StatusPending  PairRequestStatus = "pending"
	StatusApproved PairRequestStatus = "approved"
	StatusDenied   PairRequestStatus = "denied"
	StatusExpired  PairRequestStatus = "expired"
)

// PairRequest is a pending/resolved pairing request. The requester and
// owner halves are stored as canonical JSON so the self-sig bytes are
// reproducible on approve-time re-verification without reshaping.
type PairRequest struct {
	RequestID      string
	Status         PairRequestStatus
	CreatedAt      time.Time
	ExpiresAt      time.Time
	PathID         string // populated on approval, empty otherwise
	RequesterJSON  string // canonical JSON of the requester half
	OwnerJSON      string // canonical JSON of the owner half, empty until approved
	TargetNexusID  string // owner's nexus_id as claimed by the requester
}

// Pair is an active pairing between two Nexuses. Used at PUT/GET
// verification time to look up the correct pubkey for signature checks.
type Pair struct {
	PathID            string
	RequesterID       string
	RequesterPubkey   string // base64url wire-format signing pubkey
	RequesterDHPubkey string // base64url ECDH pubkey (format per DhAlg)
	OwnerID           string
	OwnerPubkey       string
	OwnerDHPubkey     string
	SigAlg            string // "ed25519" | "p256"
	DhAlg             string // "P-256" | "X25519"
	ActivatedAt       time.Time
}

// Storage is the interchange's persistence contract. Every method takes
// a context so the HTTP handler's timeout propagates to the driver.
//
// Not all methods are used by Part 2.2 — the interface is shaped now so
// Parts 2.3+ (routes, sweep) can land against a stable seam.
type Storage interface {
	// CreateSchema is idempotent: safe to call on a fresh DB or one that
	// already has the tables.
	CreateSchema(ctx context.Context) error

	// InsertEnvelope appends a new envelope. Returns ErrDuplicate if
	// msg_id already exists for the pair (caller translates to 409).
	InsertEnvelope(ctx context.Context, e Envelope) error

	// ListEnvelopes returns envelopes for pathID in the given direction,
	// strictly newer than the msg_id cursor (empty cursor = oldest
	// retained). Ordered by received_at ASC so the cursor walk is stable.
	ListEnvelopes(ctx context.Context, pathID string, dir Direction, sinceMsgID string) ([]Envelope, error)

	// DeleteEnvelopes evicts by msg_id (ack path) or by received_at
	// threshold (retention sweep). Returns evicted count.
	DeleteEnvelopesByMsgID(ctx context.Context, pathID string, ids []string) (int, error)
	DeleteEnvelopesOlderThan(ctx context.Context, cutoff time.Time) (int, error)

	// InsertPairRequest stages a new pending request. Returns
	// ErrDuplicate if request_id collides (should be infeasible — caller
	// mints UUIDs).
	InsertPairRequest(ctx context.Context, r PairRequest) error

	// GetPairRequest fetches by request_id. Returns ErrNotFound if
	// unknown.
	GetPairRequest(ctx context.Context, requestID string) (PairRequest, error)

	// ListPendingPairRequests returns pending requests (ordered oldest
	// first). Called by the tailnet-only dashboard endpoint.
	ListPendingPairRequests(ctx context.Context) ([]PairRequest, error)

	// UpdatePairRequestStatus atomically transitions from pending to
	// approved/denied/expired. Returns ErrNotFound if request_id unknown;
	// returns nil (no-op) if request is already in a terminal state so
	// concurrent sweeps don't error on already-expired rows.
	UpdatePairRequestStatus(ctx context.Context, requestID string, to PairRequestStatus, ownerJSON string, pathID string) error

	// ExpirePendingRequests marks pending requests with expires_at <
	// cutoff as expired. Returns count transitioned. Safe to call
	// idempotently.
	ExpirePendingRequests(ctx context.Context, cutoff time.Time) (int, error)

	// InsertPair records an active pair at approval time. Called from
	// within the same transaction as UpdatePairRequestStatus(approved)
	// in implementations that support transactions.
	InsertPair(ctx context.Context, p Pair) error

	// GetPair fetches an active pair by pathID. Returns ErrNotFound if
	// unknown — handlers map this to 404 on PUT /mailbox/:pathId.
	GetPair(ctx context.Context, pathID string) (Pair, error)

	// Close releases driver resources. Safe to call once; idempotent
	// behavior on repeated calls is adapter-specific.
	Close() error
}
