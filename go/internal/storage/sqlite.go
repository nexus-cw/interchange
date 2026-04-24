package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, no CGO
)

// schemaSQL creates the three tables + retention index. Kept as a single
// string so CreateSchema is one Exec call. Statements are idempotent via
// IF NOT EXISTS so re-running on an existing DB is a no-op.
//
// Column set matches the v3 spec §Storage block exactly. Additions here
// require a matching spec revision.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS envelopes (
  msg_id      TEXT PRIMARY KEY,
  path_id     TEXT NOT NULL,
  direction   TEXT NOT NULL,
  received_at TEXT NOT NULL,
  ciphertext  TEXT NOT NULL,
  signature   TEXT NOT NULL,
  outer_json  TEXT NOT NULL
);
-- Index covers the cursor walk: WHERE path_id=? AND direction=? AND msg_id>?
-- ORDER BY msg_id. UUIDv7 is timestamp-ordered so msg_id alone is both
-- the filter and the stable order.
CREATE INDEX IF NOT EXISTS idx_envelopes_path_dir ON envelopes(path_id, direction, msg_id);
CREATE INDEX IF NOT EXISTS idx_envelopes_retention ON envelopes(received_at);

CREATE TABLE IF NOT EXISTS pair_requests (
  request_id      TEXT PRIMARY KEY,
  status          TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  path_id         TEXT,
  requester_json  TEXT NOT NULL,
  owner_json      TEXT,
  -- target_nexus_id is not in the spec DDL but IS in the POST /pair/request
  -- payload. Stored so the owner dashboard can display the target without
  -- parsing requester_json.
  target_nexus_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pair_requests_status ON pair_requests(status, created_at);
CREATE INDEX IF NOT EXISTS idx_pair_requests_expiry ON pair_requests(status, expires_at);

CREATE TABLE IF NOT EXISTS pairs (
  path_id              TEXT PRIMARY KEY,
  requester_id         TEXT NOT NULL,
  requester_pubkey     TEXT NOT NULL,
  requester_dh_pubkey  TEXT NOT NULL,
  owner_id             TEXT NOT NULL,
  owner_pubkey         TEXT NOT NULL,
  owner_dh_pubkey      TEXT NOT NULL,
  sig_alg              TEXT NOT NULL,
  dh_alg               TEXT NOT NULL,
  activated_at         TEXT NOT NULL
);
`

// timeFormat is the canonical on-wire ISO 8601 UTC format used throughout
// the protocol (see v3 spec §Discovery ts_format). We round-trip times
// through this format in SQLite TEXT columns so comparison semantics are
// lexicographic and match wall-clock ordering.
const timeFormat = "2006-01-02T15:04:05Z"

// formatTime serializes a time.Time to the canonical wire format,
// coercing to UTC. Any time the storage layer writes a time column,
// it goes through here.
func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

// parseTime is the inverse; returns a UTC time.Time. Accepts either the
// canonical format or sub-second precision so timestamps written by other
// implementations still round-trip.
func parseTime(s string) (time.Time, error) {
	// Primary format first (what we write). Then fall back to RFC3339
	// nanoseconds for cross-implementation tolerance.
	if t, err := time.Parse(timeFormat, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("storage: unrecognized time format: %q", s)
}

// SQLite implements Storage against modernc.org/sqlite (pure Go).
type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens or creates a SQLite database at path. Use ":memory:"
// for tests. Sets pragmas suited to a single-process writer: WAL for
// read/write concurrency, busy_timeout so the retention sweep doesn't
// contend with live handlers, foreign_keys on for safety (even though we
// don't declare FKs today — cheap future-proofing).
func OpenSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("storage: open sqlite %q: %w", path, err)
	}
	// modernc.org/sqlite does not support multi-statement Exec, so
	// pragmas go one per call.
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("storage: %s: %w", p, err)
		}
	}
	return &SQLite{db: db}, nil
}

func (s *SQLite) Close() error { return s.db.Close() }

// CreateSchema runs schemaSQL. Idempotent.
func (s *SQLite) CreateSchema(ctx context.Context) error {
	// modernc.org/sqlite handles multiple statements in one Exec call
	// when separated by semicolons, but to be safe we split and run each.
	stmts := splitStatements(schemaSQL)
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("storage: create schema: %w (stmt=%q)", err, stmt)
		}
	}
	return nil
}

// splitStatements splits a semicolon-separated SQL script into
// individual statements. Strips single-line `-- ...` comments first so
// semicolons inside comments don't split the statement they belong to.
// Does NOT handle block comments or string literals — schemaSQL above
// contains neither.
func splitStatements(script string) []string {
	// Remove everything from `--` to end-of-line on each line.
	var cleaned strings.Builder
	for _, line := range strings.Split(script, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		cleaned.WriteString(line)
		cleaned.WriteByte('\n')
	}
	out := make([]string, 0, 8)
	for _, s := range strings.Split(cleaned.String(), ";") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// InsertEnvelope inserts a new row. A UNIQUE violation on msg_id maps to
// ErrDuplicate so the handler can return 409 without touching driver
// internals.
func (s *SQLite) InsertEnvelope(ctx context.Context, e Envelope) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO envelopes (msg_id, path_id, direction, received_at, ciphertext, signature, outer_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.MsgID, e.PathID, string(e.Direction), formatTime(e.ReceivedAt),
		e.Ciphertext, e.Signature, e.OuterJSON)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("storage: insert envelope: %w", err)
	}
	return nil
}

// ListEnvelopes returns envelopes newer than sinceMsgID. The cursor is
// msg_id (UUIDv7, timestamp-ordered) so lexicographic comparison is the
// correct order. Empty cursor means oldest.
func (s *SQLite) ListEnvelopes(ctx context.Context, pathID string, dir Direction, sinceMsgID string) ([]Envelope, error) {
	// Cursor is msg_id (UUIDv7, timestamp-ordered). Order by msg_id alone
	// keeps the filter predicate and sort aligned — avoids same-second
	// ingestion races where received_at ties would otherwise produce an
	// unstable walk. The idx_envelopes_path_dir index covers this.
	q := `
		SELECT msg_id, path_id, direction, received_at, ciphertext, signature, outer_json
		FROM envelopes
		WHERE path_id = ? AND direction = ? AND msg_id > ?
		ORDER BY msg_id ASC`
	rows, err := s.db.QueryContext(ctx, q, pathID, string(dir), sinceMsgID)
	if err != nil {
		return nil, fmt.Errorf("storage: list envelopes: %w", err)
	}
	defer rows.Close()

	var out []Envelope
	for rows.Next() {
		var e Envelope
		var direction, receivedAt string
		if err := rows.Scan(&e.MsgID, &e.PathID, &direction, &receivedAt,
			&e.Ciphertext, &e.Signature, &e.OuterJSON); err != nil {
			return nil, fmt.Errorf("storage: scan envelope: %w", err)
		}
		e.Direction = Direction(direction)
		t, err := parseTime(receivedAt)
		if err != nil {
			return nil, err
		}
		e.ReceivedAt = t
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: rows err: %w", err)
	}
	return out, nil
}

// DeleteEnvelopesByMsgID evicts acked envelopes. Bounded by the message
// cap in the ack handler, so a single IN (?, ?, ...) query is fine.
func (s *SQLite) DeleteEnvelopesByMsgID(ctx context.Context, pathID string, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1] // drop trailing comma
	args := make([]any, 0, len(ids)+1)
	args = append(args, pathID)
	for _, id := range ids {
		args = append(args, id)
	}
	q := fmt.Sprintf(`DELETE FROM envelopes WHERE path_id = ? AND msg_id IN (%s)`, placeholders)
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, fmt.Errorf("storage: delete envelopes by id: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DeleteEnvelopesOlderThan is the retention sweep path.
func (s *SQLite) DeleteEnvelopesOlderThan(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM envelopes WHERE received_at < ?`,
		formatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("storage: retention sweep: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// InsertPairRequest stages a new pending request.
func (s *SQLite) InsertPairRequest(ctx context.Context, r PairRequest) error {
	var ownerJSON, pathID any // NULL when empty
	if r.OwnerJSON != "" {
		ownerJSON = r.OwnerJSON
	}
	if r.PathID != "" {
		pathID = r.PathID
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pair_requests (request_id, status, created_at, expires_at, path_id, requester_json, owner_json, target_nexus_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.RequestID, string(r.Status), formatTime(r.CreatedAt), formatTime(r.ExpiresAt),
		pathID, r.RequesterJSON, ownerJSON, r.TargetNexusID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("storage: insert pair request: %w", err)
	}
	return nil
}

func (s *SQLite) GetPairRequest(ctx context.Context, requestID string) (PairRequest, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT request_id, status, created_at, expires_at, path_id, requester_json, owner_json, target_nexus_id
		FROM pair_requests WHERE request_id = ?`, requestID)
	return scanPairRequest(row)
}

func (s *SQLite) ListPendingPairRequests(ctx context.Context) ([]PairRequest, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT request_id, status, created_at, expires_at, path_id, requester_json, owner_json, target_nexus_id
		FROM pair_requests WHERE status = ?
		ORDER BY created_at ASC`, string(StatusPending))
	if err != nil {
		return nil, fmt.Errorf("storage: list pending: %w", err)
	}
	defer rows.Close()

	var out []PairRequest
	for rows.Next() {
		r, err := scanPairRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdatePairRequestStatus transitions a pending request. Uses a
// transaction so the status write + optional pair insert stay consistent
// on the approved path — but the pair insert is a separate call the
// caller makes inside a transaction of their own if they need that
// coupling. This method only touches pair_requests.
func (s *SQLite) UpdatePairRequestStatus(ctx context.Context, requestID string, to PairRequestStatus, ownerJSON string, pathID string) error {
	var ownerArg, pathArg any
	if ownerJSON != "" {
		ownerArg = ownerJSON
	}
	if pathID != "" {
		pathArg = pathID
	}

	// Only transition pending → terminal. If the row is already in a
	// terminal state (concurrent sweep, duplicate approval attempt),
	// return nil so the caller's flow is idempotent.
	res, err := s.db.ExecContext(ctx, `
		UPDATE pair_requests
		SET status = ?, owner_json = COALESCE(?, owner_json), path_id = COALESCE(?, path_id)
		WHERE request_id = ? AND status = ?`,
		string(to), ownerArg, pathArg, requestID, string(StatusPending))
	if err != nil {
		return fmt.Errorf("storage: update pair status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Either unknown request_id or already-terminal. Distinguish by
		// lookup so the handler can return 404 / 409 / 200 correctly.
		r, lookupErr := s.GetPairRequest(ctx, requestID)
		if lookupErr != nil {
			return lookupErr // propagates ErrNotFound
		}
		if r.Status == to {
			// Same terminal state — true idempotent no-op. The caller's
			// retry lands on the same result without side effects.
			return nil
		}
		if r.Status != StatusPending {
			// Different terminal state — e.g. deny after approve, or
			// approve after expire. Must not silently succeed.
			return ErrConflict
		}
		// Row exists, status is pending, but update affected 0 rows —
		// shouldn't happen. Surface as a driver error so it's noticed.
		return errors.New("storage: update pair status: row exists but no rows affected")
	}
	return nil
}

func (s *SQLite) ExpirePendingRequests(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE pair_requests SET status = ?
		WHERE status = ? AND expires_at < ?`,
		string(StatusExpired), string(StatusPending), formatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("storage: expire pending: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLite) InsertPair(ctx context.Context, p Pair) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pairs (path_id, requester_id, requester_pubkey, requester_dh_pubkey,
			owner_id, owner_pubkey, owner_dh_pubkey, sig_alg, dh_alg, activated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.PathID, p.RequesterID, p.RequesterPubkey, p.RequesterDHPubkey,
		p.OwnerID, p.OwnerPubkey, p.OwnerDHPubkey, p.SigAlg, p.DhAlg,
		formatTime(p.ActivatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("storage: insert pair: %w", err)
	}
	return nil
}

func (s *SQLite) GetPair(ctx context.Context, pathID string) (Pair, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT path_id, requester_id, requester_pubkey, requester_dh_pubkey,
		       owner_id, owner_pubkey, owner_dh_pubkey, sig_alg, dh_alg, activated_at
		FROM pairs WHERE path_id = ?`, pathID)

	var p Pair
	var activatedAt string
	if err := row.Scan(&p.PathID, &p.RequesterID, &p.RequesterPubkey, &p.RequesterDHPubkey,
		&p.OwnerID, &p.OwnerPubkey, &p.OwnerDHPubkey, &p.SigAlg, &p.DhAlg, &activatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Pair{}, ErrNotFound
		}
		return Pair{}, fmt.Errorf("storage: get pair: %w", err)
	}
	t, err := parseTime(activatedAt)
	if err != nil {
		return Pair{}, err
	}
	p.ActivatedAt = t
	return p, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows so the same
// logic serves single-row and iterated reads.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanPairRequest(row rowScanner) (PairRequest, error) {
	var r PairRequest
	var createdAt, expiresAt, status string
	var pathID, ownerJSON sql.NullString
	if err := row.Scan(&r.RequestID, &status, &createdAt, &expiresAt,
		&pathID, &r.RequesterJSON, &ownerJSON, &r.TargetNexusID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PairRequest{}, ErrNotFound
		}
		return PairRequest{}, fmt.Errorf("storage: scan pair request: %w", err)
	}
	r.Status = PairRequestStatus(status)
	if t, err := parseTime(createdAt); err == nil {
		r.CreatedAt = t
	} else {
		return PairRequest{}, err
	}
	if t, err := parseTime(expiresAt); err == nil {
		r.ExpiresAt = t
	} else {
		return PairRequest{}, err
	}
	if pathID.Valid {
		r.PathID = pathID.String
	}
	if ownerJSON.Valid {
		r.OwnerJSON = ownerJSON.String
	}
	return r, nil
}

// isUniqueViolation detects SQLite UNIQUE-constraint errors via error
// text. modernc.org/sqlite returns errors whose Error() contains
// "constraint failed: UNIQUE" — stable enough to match without pulling
// in the driver's error code types.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed: UNIQUE")
}
