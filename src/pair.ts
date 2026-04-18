import type { Env } from "./worker.js";
import { b64urlDecode, computePathId } from "./codec.js";

type SigAlg = "ed25519" | "p256";

interface HalfInput {
  nexus_id?: string;
  sig_alg?: string;
  pubkey?: string;
  endpoint?: string;
  nonce?: string;
  ts?: string;
  self_sig?: string;
}

interface RequestBody {
  target_nexus_id?: string;
  requester?: HalfInput;
}

interface ApproveBody {
  owner?: HalfInput;
}

interface Half {
  nexus_id: string;
  sig_alg: SigAlg;
  pubkey: string;
  pubkey_bytes: Uint8Array;
  endpoint: string;
  nonce: string;
  ts: string;
  self_sig: string;
}

const REPLAY_WINDOW_MS = 5 * 60 * 1000;
const REQUEST_TTL_MS = 24 * 60 * 60 * 1000;

// POST /pair/request — peer Nexus submits its half requesting to pair with
// the Interchange owner. Staged as `pending` until the owner approves.
export async function createPairRequest(req: Request, env: Env): Promise<Response> {
  let body: RequestBody;
  try {
    body = (await req.json()) as RequestBody;
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  if (!body.target_nexus_id) return json({ error: "missing_target" }, 400);

  const parsed = parseHalf(body.requester);
  if ("error" in parsed) return json({ error: parsed.error }, 400);
  const requester = parsed.half;

  if (!tsInWindow(requester.ts, Date.now())) {
    return json({ error: "ts_out_of_window" }, 400);
  }

  if (!(await verifySelfSig(requester))) {
    return json({ error: "bad_self_sig" }, 400);
  }

  const requestId = crypto.randomUUID();
  const now = Date.now();
  const halfJson = JSON.stringify(serializeHalf(requester));

  await env.DB
    .prepare(
      "INSERT INTO pair_requests (request_id, target_nexus_id, requester_half_json, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
    )
    .bind(requestId, body.target_nexus_id, halfJson, now)
    .run();

  return json({ request_id: requestId, status: "pending" }, 201);
}

// GET /pair/requests?status=pending — owner lists requests awaiting decision.
export async function listPairRequests(req: Request, env: Env, url: URL): Promise<Response> {
  const status = url.searchParams.get("status") ?? "pending";
  await expirePending(env);

  const { results } = await env.DB
    .prepare(
      "SELECT request_id, target_nexus_id, requester_half_json, status, created_at FROM pair_requests WHERE status = ? ORDER BY created_at ASC",
    )
    .bind(status)
    .all<{
      request_id: string;
      target_nexus_id: string;
      requester_half_json: string;
      status: string;
      created_at: number;
    }>();

  const requests = (results ?? []).map((row) => {
    const half = JSON.parse(row.requester_half_json) as ReturnType<typeof serializeHalf>;
    return {
      request_id: row.request_id,
      target_nexus_id: row.target_nexus_id,
      status: row.status,
      created_at: new Date(row.created_at).toISOString(),
      requester: {
        nexus_id: half.nexus_id,
        sig_alg: half.sig_alg,
        pubkey: half.pubkey,
        endpoint: half.endpoint,
      },
    };
  });

  return json({ requests });
}

// GET /pair/requests/:request_id — poll status; used by the requester to
// discover the owner's decision.
export async function getPairRequestStatus(
  _req: Request,
  env: Env,
  requestId: string,
): Promise<Response> {
  await expirePending(env);

  const row = await env.DB
    .prepare("SELECT request_id, status, path_id FROM pair_requests WHERE request_id = ?")
    .bind(requestId)
    .first<{ request_id: string; status: string; path_id: string | null }>();

  if (!row) return json({ error: "request_not_found" }, 404);

  const body: Record<string, unknown> = {
    request_id: row.request_id,
    status: row.status,
  };
  if (row.path_id) body.path_id = row.path_id;
  return json(body);
}

// POST /pair/requests/:request_id/approve — owner submits their half,
// activating the pair.
export async function approvePairRequest(
  req: Request,
  env: Env,
  requestId: string,
): Promise<Response> {
  let body: ApproveBody;
  try {
    body = (await req.json()) as ApproveBody;
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  await expirePending(env);

  const row = await env.DB
    .prepare(
      "SELECT request_id, requester_half_json, status FROM pair_requests WHERE request_id = ?",
    )
    .bind(requestId)
    .first<{ request_id: string; requester_half_json: string; status: string }>();

  if (!row) return json({ error: "request_not_found" }, 404);
  if (row.status !== "pending") return json({ error: "request_not_pending", status: row.status }, 409);

  const requester = rehydrateHalf(JSON.parse(row.requester_half_json));

  // Check declared sig_alg match before full parse: cross-curve submissions
  // would otherwise trip `pubkey_length` inside parseHalf and mask the real
  // error code.
  if (body.owner?.sig_alg && body.owner.sig_alg !== requester.sig_alg) {
    return json({ error: "sig_alg_mismatch" }, 400);
  }

  const parsed = parseHalf(body.owner);
  if ("error" in parsed) return json({ error: parsed.error }, 400);
  const owner = parsed.half;

  if (!tsInWindow(owner.ts, Date.now())) {
    return json({ error: "ts_out_of_window" }, 400);
  }

  if (owner.sig_alg !== requester.sig_alg) {
    return json({ error: "sig_alg_mismatch" }, 400);
  }

  if (!(await verifySelfSig(owner))) {
    return json({ error: "bad_self_sig" }, 400);
  }

  const pathId = await computePathId(requester.pubkey_bytes, owner.pubkey_bytes);

  // Canonicalise storage order by pubkey bytes: half with the smaller pubkey
  // is stored as "a". Keeps lookups deterministic regardless of who's owner
  // vs requester on a given request.
  const [first, second] = lexFirst(requester.pubkey_bytes, owner.pubkey_bytes)
    ? [requester, owner]
    : [owner, requester];

  const existing = await env.DB
    .prepare("SELECT path_id FROM pairs WHERE path_id = ?")
    .bind(pathId)
    .first<{ path_id: string }>();

  // Atomic claim of the pending→approved transition. Two concurrent
  // approvals both pass the read-side check above; only one update here
  // matches `status = 'pending'`, so only one proceeds to mint the pair.
  const claim = await env.DB
    .prepare(
      "UPDATE pair_requests SET status = 'approved', decided_at = ?, path_id = ? WHERE request_id = ? AND status = 'pending'",
    )
    .bind(Date.now(), pathId, requestId)
    .run();

  const claimed = (claim.meta as { changes?: number } | undefined)?.changes ?? 0;
  if (claimed === 0) {
    return json({ error: "request_not_pending" }, 409);
  }

  if (!existing) {
    await env.DB
      .prepare(
        "INSERT INTO pairs (path_id, sig_alg_a, pubkey_a_b64, sig_alg_b, pubkey_b_b64, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind(pathId, first.sig_alg, first.pubkey, second.sig_alg, second.pubkey, Date.now())
      .run();
  }

  return json({ request_id: requestId, status: "approved", path_id: pathId });
}

// POST /pair/requests/:request_id/deny — owner rejects a pending request.
export async function denyPairRequest(
  _req: Request,
  env: Env,
  requestId: string,
): Promise<Response> {
  await expirePending(env);

  const row = await env.DB
    .prepare("SELECT request_id, status FROM pair_requests WHERE request_id = ?")
    .bind(requestId)
    .first<{ request_id: string; status: string }>();

  if (!row) return json({ error: "request_not_found" }, 404);
  if (row.status !== "pending") return json({ error: "request_not_pending", status: row.status }, 409);

  const claim = await env.DB
    .prepare("UPDATE pair_requests SET status = 'denied', decided_at = ? WHERE request_id = ? AND status = 'pending'")
    .bind(Date.now(), requestId)
    .run();

  const claimed = (claim.meta as { changes?: number } | undefined)?.changes ?? 0;
  if (claimed === 0) {
    return json({ error: "request_not_pending" }, 409);
  }

  return json({ request_id: requestId, status: "denied" });
}

async function expirePending(env: Env): Promise<void> {
  const cutoff = Date.now() - REQUEST_TTL_MS;
  await env.DB
    .prepare("UPDATE pair_requests SET status = 'expired', decided_at = ? WHERE status = 'pending' AND created_at < ?")
    .bind(Date.now(), cutoff)
    .run();
}

function parseHalf(input: HalfInput | undefined): { half: Half } | { error: string } {
  if (!input) return { error: "missing_half" };
  const { nexus_id, sig_alg, pubkey, endpoint, nonce, ts, self_sig } = input;
  if (!nexus_id || !sig_alg || !pubkey || !nonce || !ts || !self_sig) {
    return { error: "missing_fields" };
  }
  if (!isSigAlg(sig_alg)) return { error: "unsupported_sig_alg" };

  let pubkey_bytes: Uint8Array;
  try {
    pubkey_bytes = b64urlDecode(pubkey);
  } catch {
    return { error: "pubkey_not_base64url" };
  }
  if (!isExpectedPubkeyLength(sig_alg, pubkey_bytes)) return { error: "pubkey_length" };

  return {
    half: {
      nexus_id,
      sig_alg,
      pubkey,
      pubkey_bytes,
      endpoint: endpoint ?? "",
      nonce,
      ts,
      self_sig,
    },
  };
}

function serializeHalf(h: Half) {
  return {
    nexus_id: h.nexus_id,
    sig_alg: h.sig_alg,
    pubkey: h.pubkey,
    endpoint: h.endpoint,
    nonce: h.nonce,
    ts: h.ts,
    self_sig: h.self_sig,
  };
}

function rehydrateHalf(stored: ReturnType<typeof serializeHalf>): Half {
  return {
    nexus_id: stored.nexus_id,
    sig_alg: stored.sig_alg as SigAlg,
    pubkey: stored.pubkey,
    pubkey_bytes: b64urlDecode(stored.pubkey),
    endpoint: stored.endpoint,
    nonce: stored.nonce,
    ts: stored.ts,
    self_sig: stored.self_sig,
  };
}

function canonicalHalf(half: Half): Uint8Array {
  const s = [
    "v1",
    half.nexus_id,
    half.sig_alg,
    half.pubkey,
    half.endpoint,
    half.nonce,
    half.ts,
  ].join("\n");
  return new TextEncoder().encode(s);
}

async function verifySelfSig(half: Half): Promise<boolean> {
  let sigBytes: Uint8Array;
  try {
    sigBytes = b64urlDecode(half.self_sig);
  } catch {
    return false;
  }
  const canonical = canonicalHalf(half);

  if (half.sig_alg === "ed25519") {
    if (sigBytes.length !== 64) return false;
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        half.pubkey_bytes,
        { name: "Ed25519" } as unknown as Algorithm,
        false,
        ["verify"],
      );
      return await crypto.subtle.verify(
        { name: "Ed25519" } as unknown as Algorithm,
        key,
        sigBytes,
        canonical,
      );
    } catch {
      return false;
    }
  }

  // p256 — SPKI import would be simpler, but we carry compressed SEC1 on
  // the wire, so reconstruct an uncompressed JWK for import.
  try {
    const jwk = compressedP256ToJwk(half.pubkey_bytes);
    if (!jwk) return false;
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      sigBytes,
      canonical,
    );
  } catch {
    return false;
  }
}

function compressedP256ToJwk(_bytes: Uint8Array): JsonWebKey | null {
  // Not implemented in PoC — see SPEC. Ed25519 is the default today.
  return null;
}

function isSigAlg(s: string): s is SigAlg {
  // p256 is declared in the spec but compressedP256ToJwk is unimplemented,
  // so accepting it here would surface as `bad_self_sig` — misleading.
  // Reject explicitly until the SEC1 decompression lands.
  return s === "ed25519";
}

function isExpectedPubkeyLength(alg: SigAlg, bytes: Uint8Array): boolean {
  if (alg === "ed25519") return bytes.length === 32;
  return bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03);
}

function tsInWindow(ts: string, nowMs: number): boolean {
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return false;
  return Math.abs(nowMs - t) <= REPLAY_WINDOW_MS;
}

function lexFirst(a: Uint8Array, b: Uint8Array): boolean {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! < b[i]!;
  }
  return a.length <= b.length;
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
