-- Staged-approval pair registration: peer submits a half via
-- POST /pair/request; owner reviews pending queue and approves by
-- submitting their own half, which activates the pair (inserts into
-- the `pairs` table from 0001). Pending rows are GC'd after 24h.

CREATE TABLE IF NOT EXISTS pair_requests (
  request_id           TEXT PRIMARY KEY,             -- UUIDv7
  target_nexus_id      TEXT NOT NULL,                -- owner's nexus id
  requester_half_json  TEXT NOT NULL,                -- full Half JSON as submitted
  status               TEXT NOT NULL,                -- pending | approved | denied | expired
  created_at           INTEGER NOT NULL,             -- ms since epoch
  decided_at           INTEGER,                      -- ms since epoch, nullable
  path_id              TEXT                          -- set on approve, joins to pairs.path_id
);

CREATE INDEX IF NOT EXISTS idx_pair_requests_pending
  ON pair_requests (target_nexus_id, status, created_at);
