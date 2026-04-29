package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

// newTestStore opens an in-memory SQLite + creates schema. Every test
// gets a fresh DB so there's no cross-test pollution.
func newTestStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return s
}

func TestCreateSchemaIdempotent(t *testing.T) {
	s := newTestStore(t)
	// CreateSchema was called in newTestStore; call again — must not
	// error (IF NOT EXISTS guards).
	if err := s.CreateSchema(context.Background()); err != nil {
		t.Errorf("second CreateSchema: %v", err)
	}
}

func TestEnvelopeInsertAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	env := Envelope{
		MsgID:      "0194a81e-73c4-7001-aaaa-000000000001",
		PathID:     "nxc_testpath",
		Direction:  AToB,
		ReceivedAt: now,
		Ciphertext: "base64url-ciphertext-goes-here",
		Signature:  "base64url-sig",
		OuterJSON:  `{"version":"1","msg_id":"0194a81e-73c4-7001-aaaa-000000000001"}`,
	}
	if err := s.InsertEnvelope(ctx, env); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// List without cursor — should return the envelope.
	got, err := s.ListEnvelopes(ctx, env.PathID, AToB, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("list length = %d, want 1", len(got))
	}
	if got[0].MsgID != env.MsgID {
		t.Errorf("MsgID mismatch: %q vs %q", got[0].MsgID, env.MsgID)
	}
	if !got[0].ReceivedAt.Equal(now) {
		t.Errorf("ReceivedAt drift: got %v, want %v", got[0].ReceivedAt, now)
	}
	if got[0].Direction != AToB {
		t.Errorf("Direction = %q, want A_to_B", got[0].Direction)
	}
}

func TestEnvelopeInsertDuplicate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	env := Envelope{
		MsgID:      "dup-msg-id",
		PathID:     "nxc_x",
		Direction:  AToB,
		ReceivedAt: time.Now().UTC(),
		Ciphertext: "c",
		Signature:  "s",
		OuterJSON:  "{}",
	}
	if err := s.InsertEnvelope(ctx, env); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := s.InsertEnvelope(ctx, env)
	if !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate insert err = %v, want ErrDuplicate", err)
	}
}

func TestEnvelopeListCursor(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)

	// Three envelopes, msg_ids ordered so lexicographic == chronological.
	for i, id := range []string{"m1", "m2", "m3"} {
		if err := s.InsertEnvelope(ctx, Envelope{
			MsgID:      id,
			PathID:     "p",
			Direction:  AToB,
			ReceivedAt: base.Add(time.Duration(i) * time.Second),
			Ciphertext: "c", Signature: "s", OuterJSON: "{}",
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	got, err := s.ListEnvelopes(ctx, "p", AToB, "m1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("after m1 cursor len = %d, want 2", len(got))
	}
	if got[0].MsgID != "m2" || got[1].MsgID != "m3" {
		t.Errorf("cursor walk: %v", []string{got[0].MsgID, got[1].MsgID})
	}
}

func TestEnvelopeDirectionFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.InsertEnvelope(ctx, Envelope{MsgID: "a", PathID: "p", Direction: AToB, ReceivedAt: now, Ciphertext: "c", Signature: "s", OuterJSON: "{}"})
	_ = s.InsertEnvelope(ctx, Envelope{MsgID: "b", PathID: "p", Direction: BToA, ReceivedAt: now, Ciphertext: "c", Signature: "s", OuterJSON: "{}"})

	aToB, _ := s.ListEnvelopes(ctx, "p", AToB, "")
	bToA, _ := s.ListEnvelopes(ctx, "p", BToA, "")
	if len(aToB) != 1 || aToB[0].MsgID != "a" {
		t.Errorf("A→B filter: %v", aToB)
	}
	if len(bToA) != 1 || bToA[0].MsgID != "b" {
		t.Errorf("B→A filter: %v", bToA)
	}
}

func TestEnvelopeDeleteByMsgID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"x1", "x2", "x3"} {
		_ = s.InsertEnvelope(ctx, Envelope{MsgID: id, PathID: "p", Direction: AToB, ReceivedAt: now, Ciphertext: "c", Signature: "s", OuterJSON: "{}"})
	}

	n, err := s.DeleteEnvelopesByMsgID(ctx, "p", []string{"x1", "x3", "doesnotexist"})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}

	remaining, _ := s.ListEnvelopes(ctx, "p", AToB, "")
	if len(remaining) != 1 || remaining[0].MsgID != "x2" {
		t.Errorf("remaining: %v", remaining)
	}
}

func TestEnvelopeDeleteByMsgID_EmptyList(t *testing.T) {
	s := newTestStore(t)
	n, err := s.DeleteEnvelopesByMsgID(context.Background(), "p", nil)
	if err != nil {
		t.Errorf("empty-list delete err: %v", err)
	}
	if n != 0 {
		t.Errorf("empty-list delete count = %d, want 0", n)
	}
}

func TestEnvelopeRetentionSweep(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-8 * 24 * time.Hour).Truncate(time.Second)
	fresh := time.Now().UTC().Truncate(time.Second)

	_ = s.InsertEnvelope(ctx, Envelope{MsgID: "old", PathID: "p", Direction: AToB, ReceivedAt: old, Ciphertext: "c", Signature: "s", OuterJSON: "{}"})
	_ = s.InsertEnvelope(ctx, Envelope{MsgID: "fresh", PathID: "p", Direction: AToB, ReceivedAt: fresh, Ciphertext: "c", Signature: "s", OuterJSON: "{}"})

	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	n, err := s.DeleteEnvelopesOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("swept = %d, want 1", n)
	}
	remaining, _ := s.ListEnvelopes(ctx, "p", AToB, "")
	if len(remaining) != 1 || remaining[0].MsgID != "fresh" {
		t.Errorf("remaining after sweep: %v", remaining)
	}
}

func TestPairRequestInsertAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	r := PairRequest{
		RequestID:     "req-1",
		Status:        StatusPending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
		RequesterJSON: `{"nexus_id":"bob"}`,
		TargetNexusID: "owner",
	}
	if err := s.InsertPairRequest(ctx, r); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := s.GetPairRequest(ctx, "req-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RequestID != "req-1" || got.Status != StatusPending {
		t.Errorf("round-trip: %+v", got)
	}
	if got.PathID != "" || got.OwnerJSON != "" {
		t.Errorf("empty optional fields leaked: PathID=%q OwnerJSON=%q", got.PathID, got.OwnerJSON)
	}
	if !got.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt drift: %v vs %v", got.CreatedAt, now)
	}
}

func TestPairRequestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetPairRequest(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestPairRequestListPendingOrdering(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)

	// Insert three; one non-pending.
	_ = s.InsertPairRequest(ctx, PairRequest{RequestID: "p1", Status: StatusPending, CreatedAt: base, ExpiresAt: base.Add(24 * time.Hour), RequesterJSON: "{}", TargetNexusID: "o"})
	_ = s.InsertPairRequest(ctx, PairRequest{RequestID: "p2", Status: StatusPending, CreatedAt: base.Add(1 * time.Second), ExpiresAt: base.Add(24 * time.Hour), RequesterJSON: "{}", TargetNexusID: "o"})
	_ = s.InsertPairRequest(ctx, PairRequest{RequestID: "d1", Status: StatusDenied, CreatedAt: base.Add(2 * time.Second), ExpiresAt: base.Add(24 * time.Hour), RequesterJSON: "{}", TargetNexusID: "o"})

	pending, err := s.ListPendingPairRequests(ctx)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending len = %d, want 2", len(pending))
	}
	if pending[0].RequestID != "p1" || pending[1].RequestID != "p2" {
		t.Errorf("pending order: %v", []string{pending[0].RequestID, pending[1].RequestID})
	}
}

func TestPairRequestApproveTransition(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.InsertPairRequest(ctx, PairRequest{
		RequestID: "r", Status: StatusPending, CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour), RequesterJSON: "{}", TargetNexusID: "o",
	})

	if err := s.UpdatePairRequestStatus(ctx, "r", StatusApproved, `{"nexus_id":"owner"}`, "nxc_abc"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	got, _ := s.GetPairRequest(ctx, "r")
	if got.Status != StatusApproved {
		t.Errorf("status = %q", got.Status)
	}
	if got.PathID != "nxc_abc" {
		t.Errorf("pathID = %q", got.PathID)
	}
	if got.OwnerJSON == "" {
		t.Errorf("ownerJSON not set")
	}
}

func TestPairRequestApproveIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.InsertPairRequest(ctx, PairRequest{
		RequestID: "r", Status: StatusPending, CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour), RequesterJSON: "{}", TargetNexusID: "o",
	})
	_ = s.UpdatePairRequestStatus(ctx, "r", StatusApproved, `{}`, "path")

	// Second approval attempt on an already-approved row: no error,
	// state unchanged (we don't overwrite OwnerJSON/PathID).
	err := s.UpdatePairRequestStatus(ctx, "r", StatusApproved, `{"nexus_id":"someone_else"}`, "other_path")
	if err != nil {
		t.Errorf("second approve: %v, want nil (idempotent no-op)", err)
	}
	got, _ := s.GetPairRequest(ctx, "r")
	if got.PathID != "path" {
		t.Errorf("pathID overwritten: %q", got.PathID)
	}
}

// TestPairRequestCrossTerminalConflict regression-tests the idempotency
// bug caught in Part 2.2 review: a deny after an approve (or vice versa)
// must NOT silently succeed. Must return ErrConflict so the handler can
// emit 409 rather than a misleading 200.
func TestPairRequestCrossTerminalConflict(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.InsertPairRequest(ctx, PairRequest{
		RequestID: "r", Status: StatusPending, CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour), RequesterJSON: "{}", TargetNexusID: "o",
	})
	if err := s.UpdatePairRequestStatus(ctx, "r", StatusApproved, `{}`, "path"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Deny after approve — must conflict.
	err := s.UpdatePairRequestStatus(ctx, "r", StatusDenied, "", "")
	if !errors.Is(err, ErrConflict) {
		t.Errorf("deny-after-approve err = %v, want ErrConflict", err)
	}
	// Original approval state must be intact.
	got, _ := s.GetPairRequest(ctx, "r")
	if got.Status != StatusApproved || got.PathID != "path" {
		t.Errorf("state changed after failed deny: status=%q pathID=%q", got.Status, got.PathID)
	}
}

func TestPairRequestApproveUnknown(t *testing.T) {
	s := newTestStore(t)
	err := s.UpdatePairRequestStatus(context.Background(), "unknown", StatusApproved, "{}", "p")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestExpirePendingRequests(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	// Two pending (one expired, one still valid) + one already denied
	// (whose expires_at is in the past but shouldn't be touched because
	// it's already terminal).
	_ = s.InsertPairRequest(ctx, PairRequest{RequestID: "expired", Status: StatusPending, CreatedAt: now, ExpiresAt: past, RequesterJSON: "{}", TargetNexusID: "o"})
	_ = s.InsertPairRequest(ctx, PairRequest{RequestID: "fresh", Status: StatusPending, CreatedAt: now, ExpiresAt: future, RequesterJSON: "{}", TargetNexusID: "o"})
	_ = s.InsertPairRequest(ctx, PairRequest{RequestID: "denied", Status: StatusDenied, CreatedAt: now, ExpiresAt: past, RequesterJSON: "{}", TargetNexusID: "o"})

	n, err := s.ExpirePendingRequests(ctx, now)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if n != 1 {
		t.Errorf("expired = %d, want 1", n)
	}

	r, _ := s.GetPairRequest(ctx, "expired")
	if r.Status != StatusExpired {
		t.Errorf("expired request status = %q", r.Status)
	}
	r, _ = s.GetPairRequest(ctx, "fresh")
	if r.Status != StatusPending {
		t.Errorf("fresh request got touched: %q", r.Status)
	}
	r, _ = s.GetPairRequest(ctx, "denied")
	if r.Status != StatusDenied {
		t.Errorf("denied request got touched: %q", r.Status)
	}
}

func TestPairInsertAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	p := Pair{
		PathID:            "nxc_abc",
		RequesterID:       "bob",
		RequesterPubkey:   "requester-pubkey",
		RequesterDHPubkey: "requester-dh",
		OwnerID:           "alice",
		OwnerPubkey:       "owner-pubkey",
		OwnerDHPubkey:     "owner-dh",
		SigAlg:            "ed25519",
		DhAlg:             "P-256",
		ActivatedAt:       now,
	}
	if err := s.InsertPair(ctx, p); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := s.GetPair(ctx, "nxc_abc")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RequesterID != "bob" || got.OwnerID != "alice" {
		t.Errorf("round-trip: %+v", got)
	}
	if got.SigAlg != "ed25519" || got.DhAlg != "P-256" {
		t.Errorf("alg round-trip: %q / %q", got.SigAlg, got.DhAlg)
	}
	if !got.ActivatedAt.Equal(now) {
		t.Errorf("ActivatedAt drift: %v vs %v", got.ActivatedAt, now)
	}
}

func TestPairGetNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetPair(context.Background(), "nxc_missing")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestPairDuplicateInsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p := Pair{PathID: "nxc_x", RequesterID: "a", RequesterPubkey: "r", RequesterDHPubkey: "rd",
		OwnerID: "b", OwnerPubkey: "o", OwnerDHPubkey: "od", SigAlg: "ed25519", DhAlg: "P-256", ActivatedAt: time.Now().UTC()}
	if err := s.InsertPair(ctx, p); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := s.InsertPair(ctx, p)
	if !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate err = %v, want ErrDuplicate", err)
	}
}

// TestStorageSatisfiesInterface is a compile-time check that *SQLite
// satisfies the Storage interface. Without this, renaming a method on
// the interface silently drops the SQLite implementation.
func TestStorageSatisfiesInterface(t *testing.T) {
	var _ Storage = (*SQLite)(nil)
}
