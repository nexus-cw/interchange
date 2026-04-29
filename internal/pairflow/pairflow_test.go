package pairflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nexus-cw/interchange/internal/storage"
)

// fixture stands up a real storage + a handler with deterministic clock
// and ID generator so tests can assert against known values.
func fixture(t *testing.T) (*Handler, *storage.SQLite) {
	t.Helper()
	s, err := storage.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.CreateSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	// GenID left as default (real UUIDv4). Tests retrieve request_id
	// from response bodies and pass it back as-is; no test pins an
	// exact ID value.
	h := &Handler{
		Store: s,
		Clock: func() time.Time { return time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC) },
	}
	return h, s
}

// signedHalf constructs a valid half with matching self-sig for the
// given Ed25519 keys. Used by both requester and owner fixtures.
func signedHalf(nexusID, endpoint string, ts time.Time, pub ed25519.PublicKey, priv ed25519.PrivateKey) half {
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 16))
	tsStr := ts.Format("2006-01-02T15:04:05Z")

	h := half{
		NexusID:  nexusID,
		SigAlg:   "ed25519",
		Pubkey:   pubB64,
		Endpoint: endpoint,
		Nonce:    nonce,
		Ts:       tsStr,
	}
	h.SelfSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, canonicalBytes(h)))
	h.pubkeyRaw = pub
	return h
}

// halfToWire drops the private pubkeyRaw field for JSON encoding as
// what a real client would submit over the wire.
func halfToWire(h half) map[string]string {
	return map[string]string{
		"nexus_id": h.NexusID,
		"sig_alg":  h.SigAlg,
		"pubkey":   h.Pubkey,
		"endpoint": h.Endpoint,
		"nonce":    h.Nonce,
		"ts":       h.Ts,
		"self_sig": h.SelfSig,
	}
}

// -------- createRequest tests --------

func TestCreateRequestHappyPath(t *testing.T) {
	h, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := signedHalf("bob", "https://bob.example", h.now(), pub, priv)

	body, _ := json.Marshal(map[string]any{
		"target_nexus_id": "alice",
		"requester":       halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "pending" {
		t.Errorf("status = %v, want pending", resp["status"])
	}
	if resp["request_id"] == nil {
		t.Errorf("request_id missing")
	}
}

func TestCreateRequestRejectsBadSelfSig(t *testing.T) {
	h, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := signedHalf("bob", "", h.now(), pub, priv)

	// Tamper: change endpoint AFTER signing — self-sig no longer matches.
	req.Endpoint = "https://tampered"

	body, _ := json.Marshal(map[string]any{
		"target_nexus_id": "alice",
		"requester":       halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "bad_self_sig") {
		t.Errorf("body = %s", rr.Body.String())
	}
}

func TestCreateRequestRejectsNonEd25519(t *testing.T) {
	h, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := signedHalf("bob", "", h.now(), pub, priv)
	req.SigAlg = "p256" // not supported at v1

	body, _ := json.Marshal(map[string]any{
		"target_nexus_id": "alice",
		"requester":       halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "unsupported_sig_alg") {
		t.Errorf("body = %s (want explicit unsupported_sig_alg, not bad_self_sig)", rr.Body.String())
	}
}

func TestCreateRequestRejectsStaleTs(t *testing.T) {
	h, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	stale := h.now().Add(-10 * time.Minute)
	req := signedHalf("bob", "", stale, pub, priv)

	body, _ := json.Marshal(map[string]any{
		"target_nexus_id": "alice",
		"requester":       halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "ts_out_of_window") {
		t.Errorf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestCreateRequestRejectsMissingTarget(t *testing.T) {
	h, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := signedHalf("bob", "", h.now(), pub, priv)
	body, _ := json.Marshal(map[string]any{
		"requester": halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "missing_target") {
		t.Errorf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestCreateRequestRejectsShortPubkey(t *testing.T) {
	h, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := signedHalf("bob", "", h.now(), pub, priv)
	// Swap in a pubkey that's 16 bytes instead of 32 — length check
	// must fire before signature verification.
	req.Pubkey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	body, _ := json.Marshal(map[string]any{
		"target_nexus_id": "a",
		"requester":       halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "pubkey_length") {
		t.Errorf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestCreateRequestRejectsOversizedNexusID(t *testing.T) {
	h, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	longID := strings.Repeat("x", 257)
	req := signedHalf(longID, "", h.now(), pub, priv)
	body, _ := json.Marshal(map[string]any{
		"target_nexus_id": "a",
		"requester":       halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "nexus_id_too_long") {
		t.Errorf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestCreateRequestRejectsOversizedTarget(t *testing.T) {
	h, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := signedHalf("bob", "", h.now(), pub, priv)
	body, _ := json.Marshal(map[string]any{
		"target_nexus_id": strings.Repeat("y", 257),
		"requester":       halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "target_nexus_id_too_long") {
		t.Errorf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestCreateRequestRejectsOversizedEndpoint(t *testing.T) {
	h, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := signedHalf("bob", strings.Repeat("z", 1025), h.now(), pub, priv)
	body, _ := json.Marshal(map[string]any{
		"target_nexus_id": "a",
		"requester":       halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "endpoint_too_long") {
		t.Errorf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

// -------- getRequestStatus tests --------

func TestGetStatusPending(t *testing.T) {
	h, _ := fixture(t)
	id := createPendingRequest(t, h)

	rr := doPublic(t, h, http.MethodGet, "/pair/requests/"+id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "pending" {
		t.Errorf("status = %v", resp["status"])
	}
	if _, ok := resp["path_id"]; ok {
		t.Errorf("path_id leaked on pending: %v", resp["path_id"])
	}
}

func TestGetStatusNotFound(t *testing.T) {
	h, _ := fixture(t)
	rr := doPublic(t, h, http.MethodGet, "/pair/requests/00000000-0000-4000-8000-00000000beef", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestGetStatusInvalidID(t *testing.T) {
	h, _ := fixture(t)
	rr := doPublic(t, h, http.MethodGet, "/pair/requests/not-a-uuid", nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rr.Code)
	}
}

// -------- approve / deny tests --------

func TestApproveHappyPath(t *testing.T) {
	h, s := fixture(t)
	id := createPendingRequest(t, h)

	// Owner half
	ownPub, ownPriv, _ := ed25519.GenerateKey(nil)
	owner := signedHalf("alice", "", h.now(), ownPub, ownPriv)
	body, _ := json.Marshal(map[string]any{"owner": halfToWire(owner)})
	rr := doOwner(t, h, http.MethodPost, "/pair/requests/"+id+"/approve", body)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "approved" {
		t.Errorf("status = %v", resp["status"])
	}
	pathID, _ := resp["path_id"].(string)
	if pathID == "" || !strings.HasPrefix(pathID, "nxc_") {
		t.Errorf("path_id = %q", pathID)
	}

	// Pair row exists.
	pair, err := s.GetPair(context.Background(), pathID)
	if err != nil {
		t.Fatalf("GetPair: %v", err)
	}
	if pair.OwnerID != "alice" {
		t.Errorf("owner = %q", pair.OwnerID)
	}

	// Request flipped to approved.
	req, _ := s.GetPairRequest(context.Background(), id)
	if req.Status != storage.StatusApproved || req.PathID != pathID {
		t.Errorf("req after approve: %+v", req)
	}
}

func TestApproveRejectsBadOwnerSig(t *testing.T) {
	h, _ := fixture(t)
	id := createPendingRequest(t, h)
	ownPub, ownPriv, _ := ed25519.GenerateKey(nil)
	owner := signedHalf("alice", "", h.now(), ownPub, ownPriv)
	// Tamper after signing.
	owner.Endpoint = "tampered"
	body, _ := json.Marshal(map[string]any{"owner": halfToWire(owner)})
	rr := doOwner(t, h, http.MethodPost, "/pair/requests/"+id+"/approve", body)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "bad_self_sig") {
		t.Errorf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestApproveDoubleApprovalIsIdempotent(t *testing.T) {
	h, _ := fixture(t)
	id := createPendingRequest(t, h)
	ownPub, ownPriv, _ := ed25519.GenerateKey(nil)
	owner := signedHalf("alice", "", h.now(), ownPub, ownPriv)
	body, _ := json.Marshal(map[string]any{"owner": halfToWire(owner)})
	rr := doOwner(t, h, http.MethodPost, "/pair/requests/"+id+"/approve", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("first approve: %d", rr.Code)
	}

	// Second approve with same owner — should be idempotent-OK (pair
	// exists, requester+owner pubkeys match).
	rr = doOwner(t, h, http.MethodPost, "/pair/requests/"+id+"/approve", body)
	if rr.Code != http.StatusOK {
		t.Errorf("second approve status = %d, want 200 (idempotent)", rr.Code)
	}
}

// TestApproveIdempotencyRejectsForeignOwner — the double-approve idempotency
// path must NOT return 200 if a third-party posts their own "owner" half
// to an already-approved request. Only the real owner's resubmission
// should succeed idempotently.
func TestApproveIdempotencyRejectsForeignOwner(t *testing.T) {
	h, _ := fixture(t)
	id := createPendingRequest(t, h)

	// First approve with real owner.
	realPub, realPriv, _ := ed25519.GenerateKey(nil)
	realOwner := signedHalf("alice", "", h.now(), realPub, realPriv)
	body, _ := json.Marshal(map[string]any{"owner": halfToWire(realOwner)})
	if rr := doOwner(t, h, http.MethodPost, "/pair/requests/"+id+"/approve", body); rr.Code != http.StatusOK {
		t.Fatalf("first approve: %d", rr.Code)
	}

	// Foreign party posts their OWN owner half — different pubkey,
	// valid self-sig for their key.
	fakePub, fakePriv, _ := ed25519.GenerateKey(nil)
	fakeOwner := signedHalf("eve", "", h.now(), fakePub, fakePriv)
	body, _ = json.Marshal(map[string]any{"owner": halfToWire(fakeOwner)})
	rr := doOwner(t, h, http.MethodPost, "/pair/requests/"+id+"/approve", body)
	if rr.Code != http.StatusConflict {
		t.Errorf("foreign owner on approved request: %d, want 409", rr.Code)
	}
	// The 409 body carries the current status ("approved") for context;
	// that's fine. What MUST NOT happen is the idempotent 200 path:
	// check the body is not the approved-response shape {request_id,
	// status:"approved", path_id:...} which would include a path_id.
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if _, leaks := resp["path_id"]; leaks {
		t.Errorf("foreign owner leaked pathId: %s", rr.Body.String())
	}
	if resp["error"] == nil {
		t.Errorf("foreign-owner response missing error field: %s", rr.Body.String())
	}
}

func TestApproveNotFound(t *testing.T) {
	h, _ := fixture(t)
	ownPub, ownPriv, _ := ed25519.GenerateKey(nil)
	owner := signedHalf("alice", "", h.now(), ownPub, ownPriv)
	body, _ := json.Marshal(map[string]any{"owner": halfToWire(owner)})
	rr := doOwner(t, h, http.MethodPost, "/pair/requests/00000000-0000-4000-8000-00000000dead/approve", body)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestDenyHappyPath(t *testing.T) {
	h, s := fixture(t)
	id := createPendingRequest(t, h)

	rr := doOwner(t, h, http.MethodPost, "/pair/requests/"+id+"/deny", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}

	req, _ := s.GetPairRequest(context.Background(), id)
	if req.Status != storage.StatusDenied {
		t.Errorf("status = %q, want denied", req.Status)
	}
}

// TestDenyAfterApproveIsConflict — regression pinning the ErrConflict
// path added in Part 2.2 review. Ensures deny after approve doesn't
// silently succeed and corrupt the pair record.
func TestDenyAfterApproveIsConflict(t *testing.T) {
	h, s := fixture(t)
	id := createPendingRequest(t, h)

	// Approve first.
	ownPub, ownPriv, _ := ed25519.GenerateKey(nil)
	owner := signedHalf("alice", "", h.now(), ownPub, ownPriv)
	body, _ := json.Marshal(map[string]any{"owner": halfToWire(owner)})
	rr := doOwner(t, h, http.MethodPost, "/pair/requests/"+id+"/approve", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}

	// Deny attempt — must 409.
	rr = doOwner(t, h, http.MethodPost, "/pair/requests/"+id+"/deny", nil)
	if rr.Code != http.StatusConflict {
		t.Errorf("deny after approve status = %d, want 409 (ErrConflict)", rr.Code)
	}
	// Request stayed approved.
	req, _ := s.GetPairRequest(context.Background(), id)
	if req.Status != storage.StatusApproved {
		t.Errorf("state changed after failed deny: %q", req.Status)
	}
}

// -------- listing tests --------

func TestListPendingReturnsStagedRequests(t *testing.T) {
	h, _ := fixture(t)
	_ = createPendingRequest(t, h)
	_ = createPendingRequest(t, h)

	rr := doOwner(t, h, http.MethodGet, "/pair/requests?status=pending", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Requests []map[string]any `json:"requests"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Requests) != 2 {
		t.Errorf("len = %d, want 2", len(resp.Requests))
	}
	// requester field should NOT contain self_sig (dashboard trimming).
	req0 := resp.Requests[0]["requester"].(map[string]any)
	if _, leaks := req0["self_sig"]; leaks {
		t.Errorf("self_sig leaked into listing response")
	}
}

func TestListPendingRejectsOtherStatus(t *testing.T) {
	h, _ := fixture(t)
	rr := doOwner(t, h, http.MethodGet, "/pair/requests?status=approved", nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rr.Code)
	}
}

// -------- owner auth tests --------

func TestOwnerSecretRequired(t *testing.T) {
	h, _ := fixture(t)
	h.OwnerSecret = "s3cret"
	rr := doOwner(t, h, http.MethodGet, "/pair/requests?status=pending", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 without shared secret", rr.Code)
	}
}

func TestOwnerSecretAccepted(t *testing.T) {
	h, _ := fixture(t)
	h.OwnerSecret = "s3cret"

	req := httptest.NewRequest(http.MethodGet, "/pair/requests?status=pending", nil)
	req.Header.Set("X-Owner-Secret", "s3cret")
	rr := httptest.NewRecorder()
	h.OwnerRoutes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d with correct secret", rr.Code)
	}
}

// -------- pathId derivation tests --------

func TestComputePathIDIsCommutative(t *testing.T) {
	a := bytes.Repeat([]byte{1}, 32)
	b := bytes.Repeat([]byte{2}, 32)
	p1 := computePathID(a, b)
	p2 := computePathID(b, a)
	if p1 != p2 {
		t.Errorf("pathId not commutative: %s != %s", p1, p2)
	}
}

func TestComputePathIDPrefix(t *testing.T) {
	p := computePathID(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if !strings.HasPrefix(p, "nxc_") {
		t.Errorf("pathId lacks nxc_ prefix: %s", p)
	}
	// 43 chars after prefix (base64url of 32-byte SHA-256).
	if len(p) != 47 {
		t.Errorf("pathId length = %d, want 47 (4 prefix + 43 b64url)", len(p))
	}
}

// -------- canonicalBytes interop test --------

// TestCanonicalBytesFormat pins the exact byte layout the self-sig is
// computed over. v3 spec §Components.2 Pairing.self_sig_canonical is
// the contract; divergence here silently breaks interop with any peer
// that canonicalises differently.
func TestCanonicalBytesFormat(t *testing.T) {
	h := half{
		NexusID:  "bob",
		SigAlg:   "ed25519",
		Pubkey:   "abcdef",
		Endpoint: "https://bob",
		Nonce:    "noncebytes",
		Ts:       "2026-04-25T12:00:00Z",
	}
	got := string(canonicalBytes(h))
	want := "v1\nbob\ned25519\nabcdef\nhttps://bob\nnoncebytes\n2026-04-25T12:00:00Z"
	if got != want {
		t.Errorf("canonical mismatch.\ngot:  %q\nwant: %q", got, want)
	}
	// No trailing newline.
	if strings.HasSuffix(got, "\n") {
		t.Errorf("trailing newline in canonical bytes")
	}
}

// -------- helpers --------

// createPendingRequest seeds a valid pending request and returns its ID.
// Used as setup for approve/deny/list tests.
func createPendingRequest(t *testing.T, h *Handler) string {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	req := signedHalf("bob", "https://bob.example", h.now(), pub, priv)
	body, _ := json.Marshal(map[string]any{
		"target_nexus_id": "alice",
		"requester":       halfToWire(req),
	})
	rr := doPublic(t, h, http.MethodPost, "/pair/request", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("seed create: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	return resp["request_id"].(string)
}

func doPublic(t *testing.T, h *Handler, method, url string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, url, r)
	rr := httptest.NewRecorder()
	h.PublicRoutes().ServeHTTP(rr, req)
	return rr
}

func doOwner(t *testing.T, h *Handler, method, url string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, url, r)
	rr := httptest.NewRecorder()
	h.OwnerRoutes().ServeHTTP(rr, req)
	return rr
}
