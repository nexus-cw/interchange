import type { Env } from "./worker.js";
import { b64urlDecode, computePathId } from "./codec.js";

type SigAlg = "ed25519" | "p256";

interface HalfInput {
  sig_alg?: string;
  pubkey?: string;
}

interface PairBody {
  a?: HalfInput;
  b?: HalfInput;
}

export async function registerPair(req: Request, env: Env): Promise<Response> {
  let body: PairBody;
  try {
    body = (await req.json()) as PairBody;
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  const a = body.a;
  const b = body.b;
  if (!a || !b || !a.sig_alg || !a.pubkey || !b.sig_alg || !b.pubkey) {
    return json({ error: "missing_fields" }, 400);
  }

  if (!isSigAlg(a.sig_alg) || !isSigAlg(b.sig_alg)) {
    return json({ error: "unsupported_sig_alg" }, 400);
  }

  if (a.sig_alg !== b.sig_alg) {
    return json({ error: "sig_alg_mismatch" }, 400);
  }

  let pubA: Uint8Array;
  let pubB: Uint8Array;
  try {
    pubA = b64urlDecode(a.pubkey);
    pubB = b64urlDecode(b.pubkey);
  } catch {
    return json({ error: "pubkey_not_base64url" }, 400);
  }

  if (!isExpectedPubkeyLength(a.sig_alg, pubA) || !isExpectedPubkeyLength(b.sig_alg, pubB)) {
    return json({ error: "pubkey_length" }, 400);
  }

  const pathId = await computePathId(pubA, pubB);

  // Canonicalise storage order by pubkey bytes: the half with the smaller
  // pubkey is stored as "a". Keeps lookups deterministic regardless of
  // which side registered first.
  const [firstPub, secondPub, firstAlg, secondAlg] = lexFirst(pubA, pubB)
    ? [a.pubkey, b.pubkey, a.sig_alg, b.sig_alg]
    : [b.pubkey, a.pubkey, b.sig_alg, a.sig_alg];

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
    const sameA = existing.pubkey_a_b64 === firstPub && existing.sig_alg_a === firstAlg;
    const sameB = existing.pubkey_b_b64 === secondPub && existing.sig_alg_b === secondAlg;
    if (sameA && sameB) {
      return json({ path_id: pathId, existed: true }, 409);
    }
    return json({ error: "path_id_collision" }, 409);
  }

  await env.DB
    .prepare(
      "INSERT INTO pairs (path_id, sig_alg_a, pubkey_a_b64, sig_alg_b, pubkey_b_b64, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(pathId, firstAlg, firstPub, secondAlg, secondPub, Date.now())
    .run();

  return json({ path_id: pathId }, 201);
}

function isSigAlg(s: string): s is SigAlg {
  return s === "ed25519" || s === "p256";
}

function isExpectedPubkeyLength(alg: SigAlg, bytes: Uint8Array): boolean {
  if (alg === "ed25519") return bytes.length === 32;
  // p256: compressed SEC1 point = 33 bytes with 0x02/0x03 prefix.
  return bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03);
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
