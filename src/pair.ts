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

interface PairBody {
  a?: HalfInput;
  b?: HalfInput;
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

export async function registerPair(req: Request, env: Env): Promise<Response> {
  let body: PairBody;
  try {
    body = (await req.json()) as PairBody;
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  // Check declared sig_alg match before per-half validation: cross-alg
  // pairings are rejected with their own error code, rather than leaking
  // out as a "pubkey_length" error on whichever half mismatches the curve.
  const aAlg = body.a?.sig_alg;
  const bAlg = body.b?.sig_alg;
  if (aAlg && bAlg && aAlg !== bAlg) {
    return json({ error: "sig_alg_mismatch" }, 400);
  }

  const aParsed = parseHalf(body.a);
  if ("error" in aParsed) return json({ error: aParsed.error }, 400);
  const bParsed = parseHalf(body.b);
  if ("error" in bParsed) return json({ error: bParsed.error }, 400);
  const a = aParsed.half;
  const b = bParsed.half;

  if (a.sig_alg !== b.sig_alg) {
    return json({ error: "sig_alg_mismatch" }, 400);
  }

  const now = Date.now();
  if (!tsInWindow(a.ts, now) || !tsInWindow(b.ts, now)) {
    return json({ error: "ts_out_of_window" }, 400);
  }

  if (!(await verifySelfSig(a)) || !(await verifySelfSig(b))) {
    return json({ error: "bad_self_sig" }, 400);
  }

  const pathId = await computePathId(a.pubkey_bytes, b.pubkey_bytes);

  // Canonicalise storage order by pubkey bytes: half with the smaller
  // pubkey is stored as "a". Keeps lookups deterministic regardless of
  // submission order.
  const [first, second] = lexFirst(a.pubkey_bytes, b.pubkey_bytes) ? [a, b] : [b, a];

  const existing = await env.DB
    .prepare("SELECT path_id, sig_alg_a, pubkey_a_b64, sig_alg_b, pubkey_b_b64 FROM pairs WHERE path_id = ?")
    .bind(pathId)
    .first<{
      path_id: string;
      sig_alg_a: string;
      pubkey_a_b64: string;
      sig_alg_b: string;
      pubkey_b_b64: string;
    }>();

  if (existing) {
    const match =
      existing.pubkey_a_b64 === first.pubkey &&
      existing.sig_alg_a === first.sig_alg &&
      existing.pubkey_b_b64 === second.pubkey &&
      existing.sig_alg_b === second.sig_alg;
    if (match) return json({ path_id: pathId, existed: true }, 409);
    return json({ error: "path_id_collision" }, 409);
  }

  await env.DB
    .prepare(
      "INSERT INTO pairs (path_id, sig_alg_a, pubkey_a_b64, sig_alg_b, pubkey_b_b64, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(pathId, first.sig_alg, first.pubkey, second.sig_alg, second.pubkey, now)
    .run();

  return json({ path_id: pathId }, 201);
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

// Compressed SEC1 → JWK. Decompression via modular sqrt over the P-256 field.
// Kept isolated so the Ed25519 path stays tiny.
function compressedP256ToJwk(_bytes: Uint8Array): JsonWebKey | null {
  // Not needed for v0.1 tests (all ed25519). Implementing this is real work
  // for p256-signing Nexuses; left as a follow-up so the Ed25519 path can
  // land first. The endpoint will refuse p256 verification until it's done.
  return null;
}

function isSigAlg(s: string): s is SigAlg {
  return s === "ed25519" || s === "p256";
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
