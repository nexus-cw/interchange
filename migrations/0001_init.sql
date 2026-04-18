-- Initial schema for the Interchange Mailbox + pair registry.
--
-- The Mailbox is append-only per direction. Readers filter by
-- `dest_pubkey_b64` so each Nexus in a pair pulls only envelopes
-- addressed to it. Dedupe is the receiving Frame's job — the
-- Interchange keeps everything until either an explicit ack or the
-- retention-window eviction alarm sweeps it.

CREATE TABLE IF NOT EXISTS pairs (
  path_id          TEXT PRIMARY KEY,
  sig_alg_a        TEXT NOT NULL,
  pubkey_a_b64     TEXT NOT NULL,
  sig_alg_b        TEXT NOT NULL,
  pubkey_b_b64     TEXT NOT NULL,
  registered_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS envelopes (
  msg_id              TEXT PRIMARY KEY,            -- UUIDv7
  path_id             TEXT NOT NULL,
  sender_pubkey_b64   TEXT NOT NULL,
  dest_pubkey_b64     TEXT NOT NULL,
  ts                  TEXT NOT NULL,               -- ISO-8601
  received_at         INTEGER NOT NULL,            -- ms since epoch, server-assigned
  ciphertext_sha256   TEXT NOT NULL,               -- hex
  envelope_json       TEXT NOT NULL,               -- canonical outer envelope
  signature_b64       TEXT NOT NULL                -- X-Nexus-Signature value
);

CREATE INDEX IF NOT EXISTS idx_envelopes_pull
  ON envelopes (path_id, dest_pubkey_b64, msg_id);

CREATE INDEX IF NOT EXISTS idx_envelopes_retention
  ON envelopes (received_at);
