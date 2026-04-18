// D1-backed Mailbox operations. Free-tier PoC storage — strong consistency,
// SQL-shaped. Same append / list-since / ack shape the DO version would
// expose, so the Paid-tier upgrade to a per-pair DO is a swap, not a
// protocol change.
//
// The Interchange is content-blind: it stores the outer (cleartext-routing,
// AEAD-inner) envelope verbatim. It does not decrypt.

import type { Env } from "./worker.js";
import { b64urlDecode, canonicalJson } from "./codec.js";

const REPLAY_WINDOW_MS = 5 * 60 * 1000;

interface PairRow {
  path_id: string;
  sig_alg_a: string;
  pubkey_a_b64: string;
  sig_alg_b: string;
  pubkey_b_b64: string;
}

interface OuterEnvelope {
  version?: string;
  msg_id?: string;
  ts?: string;
  path_id?: string;
  ciphertext_sha256?: string;
  ciphertext?: string;
}

// PUT /mailbox/:pathId — append a signed outer envelope.
export async function appendEnvelope(req: Request, env: Env, pathId: string): Promise<Response> {
  const pair = await loadPair(env, pathId);
  if (!pair) return json({ error: "pair_not_found" }, 404);

  const rawBody = await req.text();
  let envelope: OuterEnvelope;
  try {
    envelope = JSON.parse(rawBody) as OuterEnvelope;
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  // Schema guards.
  if (
    envelope.version !== "1" ||
    !envelope.msg_id ||
    !envelope.ts ||
    !envelope.path_id ||
    !envelope.ciphertext_sha256 ||
    !envelope.ciphertext
  ) {
    return json({ error: "invalid_envelope" }, 400);
  }

  if (envelope.path_id !== pathId) {
    return json({ error: "path_id_mismatch" }, 400);
  }

  if (!isUuidv7(envelope.msg_id)) {
    return json({ error: "invalid_msg_id" }, 400);
  }

  if (!tsInWindow(envelope.ts, Date.now())) {
    return json({ error: "ts_out_of_window" }, 400);
  }

  // Ciphertext hash integrity.
  let ctBytes: Uint8Array;
  try {
    ctBytes = b64urlDecode(envelope.ciphertext);
  } catch {
    return json({ error: "ciphertext_not_base64url" }, 400);
  }
  const digest = await crypto.subtle.digest("SHA-256", ctBytes);
  if (bytesToHex(new Uint8Array(digest)) !== envelope.ciphertext_sha256) {
    return json({ error: "ciphertext_hash_mismatch" }, 400);
  }

  // Signature — verify over the server-recanonicalized bytes, not the raw
  // body. If the client built canonical JSON correctly these match; if they
  // didn't, re-canonicalizing here gives cross-runtime parity a fighting
  // chance rather than silently 401-ing on whitespace/key-order drift.
  const sigHeader = req.headers.get("x-nexus-signature") ?? "";
  const canonical = new TextEncoder().encode(canonicalJson(envelope));
  const sender = await identifyCaller(pair, sigHeader, canonical);
  if (!sender) return json({ error: "signature_invalid" }, 401);

  const destPubkey = sender.pubkey === pair.pubkey_a_b64 ? pair.pubkey_b_b64 : pair.pubkey_a_b64;

  // Duplicate msg_id is informational — tell the client we already have it.
  const existing = await env.DB
    .prepare("SELECT msg_id FROM envelopes WHERE msg_id = ?")
    .bind(envelope.msg_id)
    .first<{ msg_id: string }>();
  if (existing) return json({ error: "duplicate_msg_id" }, 409);

  await env.DB
    .prepare(
      "INSERT INTO envelopes (msg_id, path_id, sender_pubkey_b64, dest_pubkey_b64, ts, received_at, ciphertext_sha256, envelope_json, signature_b64) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      envelope.msg_id,
      pathId,
      sender.pubkey,
      destPubkey,
      envelope.ts,
      Date.now(),
      envelope.ciphertext_sha256,
      rawBody,
      sigHeader,
    )
    .run();

  return json({ msg_id: envelope.msg_id }, 202);
}

// GET /mailbox/:pathId?since=<msg_id> — caller's inbox. Caller is identified
// by X-Nexus-Signature over the path-and-query string.
export async function listSince(req: Request, env: Env, pathId: string, url: URL): Promise<Response> {
  const pair = await loadPair(env, pathId);
  if (!pair) return json({ error: "pair_not_found" }, 404);

  const sigHeader = req.headers.get("x-nexus-signature") ?? "";
  const pathAndQuery = url.pathname + (url.search || "");
  const canonical = new TextEncoder().encode(pathAndQuery);
  const caller = await identifyCaller(pair, sigHeader, canonical);
  if (!caller) return json({ error: "signature_invalid" }, 401);

  const since = url.searchParams.get("since");
  if (since !== null && !isUuidv7(since)) {
    return json({ error: "invalid_since" }, 400);
  }
  const query = since
    ? "SELECT msg_id, envelope_json FROM envelopes WHERE path_id = ? AND dest_pubkey_b64 = ? AND msg_id > ? ORDER BY msg_id ASC"
    : "SELECT msg_id, envelope_json FROM envelopes WHERE path_id = ? AND dest_pubkey_b64 = ? ORDER BY msg_id ASC";
  const stmt = since
    ? env.DB.prepare(query).bind(pathId, caller.pubkey, since)
    : env.DB.prepare(query).bind(pathId, caller.pubkey);
  const { results } = await stmt.all<{ msg_id: string; envelope_json: string }>();

  const envelopes = (results ?? []).map((row) => JSON.parse(row.envelope_json));
  const cursor = results && results.length > 0 ? results[results.length - 1]!.msg_id : null;
  return json({ envelopes, cursor });
}

// POST /mailbox/:pathId/ack — evict acked envelopes addressed to the caller.
export async function ackEnvelopes(req: Request, env: Env, pathId: string): Promise<Response> {
  const pair = await loadPair(env, pathId);
  if (!pair) return json({ error: "pair_not_found" }, 404);

  const sigHeader = req.headers.get("x-nexus-signature") ?? "";
  const canonical = new TextEncoder().encode(`/mailbox/${pathId}/ack`);
  const caller = await identifyCaller(pair, sigHeader, canonical);
  if (!caller) return json({ error: "signature_invalid" }, 401);

  let body: { ids?: unknown };
  try {
    body = (await req.json()) as { ids?: unknown };
  } catch {
    return json({ error: "invalid_json" }, 400);
  }
  const ids = Array.isArray(body.ids) ? body.ids.filter((s): s is string => typeof s === "string") : [];
  if (ids.length === 0) return json({ evicted: 0 });
  // D1 caps bound parameters per prepared statement; keep well under the
  // limit. Callers needing to ack more should batch.
  if (ids.length > 100) return json({ error: "too_many_ids", max: 100 }, 400);

  // Only evict rows addressed to the caller; one side cannot delete the
  // other's inbox.
  const placeholders = ids.map(() => "?").join(",");
  const result = await env.DB
    .prepare(
      `DELETE FROM envelopes WHERE path_id = ? AND dest_pubkey_b64 = ? AND msg_id IN (${placeholders})`,
    )
    .bind(pathId, caller.pubkey, ...ids)
    .run();
  const evicted = (result.meta as { changes?: number } | undefined)?.changes ?? 0;
  return json({ evicted });
}

async function loadPair(env: Env, pathId: string): Promise<PairRow | null> {
  return env.DB
    .prepare("SELECT path_id, sig_alg_a, pubkey_a_b64, sig_alg_b, pubkey_b_b64 FROM pairs WHERE path_id = ?")
    .bind(pathId)
    .first<PairRow>();
}

// Try each pubkey of the pair; the one whose signature verifies is the caller.
// O(2) verifications — cheap. Fails on unregistered pubkeys (impostor case).
async function identifyCaller(
  pair: PairRow,
  sigB64: string,
  message: Uint8Array,
): Promise<{ pubkey: string; sig_alg: string } | null> {
  if (!sigB64) return null;
  let sig: Uint8Array;
  try {
    sig = b64urlDecode(sigB64);
  } catch {
    return null;
  }
  for (const half of [
    { pubkey: pair.pubkey_a_b64, sig_alg: pair.sig_alg_a },
    { pubkey: pair.pubkey_b_b64, sig_alg: pair.sig_alg_b },
  ]) {
    if (await verify(half.sig_alg, half.pubkey, sig, message)) return half;
  }
  return null;
}

async function verify(
  sigAlg: string,
  pubkeyB64: string,
  sig: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (sigAlg !== "ed25519") return false; // p256 pending; see SPEC v0.1 note
  if (sig.length !== 64) return false;
  let pubBytes: Uint8Array;
  try {
    pubBytes = b64urlDecode(pubkeyB64);
  } catch {
    return false;
  }
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      pubBytes,
      { name: "Ed25519" } as unknown as Algorithm,
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "Ed25519" } as unknown as Algorithm,
      key,
      sig,
      message,
    );
  } catch {
    return false;
  }
}

function isUuidv7(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s);
}

function tsInWindow(ts: string, nowMs: number): boolean {
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return false;
  return Math.abs(nowMs - t) <= REPLAY_WINDOW_MS;
}

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, "0");
  return s;
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
