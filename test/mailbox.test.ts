import { describe, it, expect, beforeEach } from "vitest";
import { SELF } from "cloudflare:test";
import { applyMigrations } from "./setup.js";
import {
  makeEd25519Identity,
  makeOuterEnvelope,
  signPath,
  canonicalJson,
  uuidv7,
  b64urlEncode,
  type Ed25519Identity,
} from "./helpers.js";

beforeEach(async () => {
  await applyMigrations();
});

// Walks the staged-approval dance once so mailbox tests have a live pair.
async function activePair(): Promise<{ a: Ed25519Identity; b: Ed25519Identity; pathId: string }> {
  const a = await makeEd25519Identity("nexus-alpha");
  const b = await makeEd25519Identity("nexus-beta");
  const reqRes = await SELF.fetch("https://example.com/pair/request", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ target_nexus_id: "nexus-beta", requester: a.half }),
  });
  const { request_id } = (await reqRes.json()) as { request_id: string };
  const approveRes = await SELF.fetch(`https://example.com/pair/requests/${request_id}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ owner: b.half }),
  });
  const approveJson = (await approveRes.json()) as { path_id: string };
  return { a, b, pathId: approveJson.path_id };
}

async function putEnvelope(pathId: string, envelope: unknown, signature: string): Promise<Response> {
  return SELF.fetch(`https://example.com/mailbox/${pathId}`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      "x-nexus-signature": signature,
    },
    body: canonicalJson(envelope),
  });
}

async function getMailbox(
  pathId: string,
  caller: Ed25519Identity,
  since?: string,
): Promise<Response> {
  const pathAndQuery = since
    ? `/mailbox/${pathId}?since=${since}`
    : `/mailbox/${pathId}`;
  const signature = await signPath(caller.keyPair, pathAndQuery);
  return SELF.fetch(`https://example.com${pathAndQuery}`, {
    headers: { "x-nexus-signature": signature },
  });
}

async function ackEnvelopes(
  pathId: string,
  caller: Ed25519Identity,
  ids: string[],
): Promise<Response> {
  const body = JSON.stringify({ ids });
  const signature = await signPath(caller.keyPair, `/mailbox/${pathId}/ack`);
  return SELF.fetch(`https://example.com/mailbox/${pathId}/ack`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-nexus-signature": signature,
    },
    body,
  });
}

describe("PUT /mailbox/:pathId", () => {
  it("accepts a valid signed envelope with 202", async () => {
    const { a, pathId } = await activePair();
    const ct = new TextEncoder().encode("hello ciphertext");
    const { envelope, signature } = await makeOuterEnvelope(a, pathId, ct);
    const res = await putEnvelope(pathId, envelope, signature);
    expect(res.status).toBe(202);
  });

  it("rejects with 404 when pathId has no registered pair", async () => {
    const a = await makeEd25519Identity("nexus-alpha");
    const ghostPath = "nxc_" + "A".repeat(43);
    const ct = new TextEncoder().encode("x");
    const { envelope, signature } = await makeOuterEnvelope(a, ghostPath, ct);
    const res = await putEnvelope(ghostPath, envelope, signature);
    expect(res.status).toBe(404);
  });

  it("rejects with 400 when envelope.path_id disagrees with URL", async () => {
    const { a, pathId } = await activePair();
    const otherPath = "nxc_" + "B".repeat(43);
    const ct = new TextEncoder().encode("x");
    const { envelope, signature } = await makeOuterEnvelope(a, otherPath, ct);
    // URL says one path, body says another.
    const res = await SELF.fetch(`https://example.com/mailbox/${pathId}`, {
      method: "PUT",
      headers: { "content-type": "application/json", "x-nexus-signature": signature },
      body: canonicalJson(envelope),
    });
    expect(res.status).toBe(400);
  });

  it("rejects with 401 when signature doesn't verify (wrong key)", async () => {
    const { pathId } = await activePair();
    const impostor = await makeEd25519Identity("nexus-impostor");
    const ct = new TextEncoder().encode("evil");
    const { envelope, signature } = await makeOuterEnvelope(impostor, pathId, ct);
    const res = await putEnvelope(pathId, envelope, signature);
    expect(res.status).toBe(401);
  });

  it("rejects with 400 when ciphertext_sha256 doesn't match payload", async () => {
    const { a, pathId } = await activePair();
    const ct = new TextEncoder().encode("real");
    const { envelope, signature } = await makeOuterEnvelope(a, pathId, ct);
    // Corrupt the hash after signing — the Interchange re-computes and should
    // reject. Sig still verifies over the tampered bytes since we re-sign.
    const broken = { ...envelope, ciphertext_sha256: "00".repeat(32) };
    const canonical = new TextEncoder().encode(canonicalJson(broken));
    const badSig = b64urlEncode(
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "Ed25519" } as unknown as Algorithm,
          a.keyPair.privateKey,
          canonical,
        ),
      ),
    );
    const res = await putEnvelope(pathId, broken, badSig);
    expect(res.status).toBe(400);
  });

  it("rejects stale ts with 400", async () => {
    const { a, pathId } = await activePair();
    const stale = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const ct = new TextEncoder().encode("x");
    const { envelope, signature } = await makeOuterEnvelope(a, pathId, ct, { ts: stale });
    const res = await putEnvelope(pathId, envelope, signature);
    expect(res.status).toBe(400);
  });

  it("rejects duplicate msg_id with 409", async () => {
    const { a, pathId } = await activePair();
    const ct = new TextEncoder().encode("dup");
    const msgId = uuidv7();
    const first = await makeOuterEnvelope(a, pathId, ct, { msgId });
    const r1 = await putEnvelope(pathId, first.envelope, first.signature);
    expect(r1.status).toBe(202);
    const ct2 = new TextEncoder().encode("dup2");
    const second = await makeOuterEnvelope(a, pathId, ct2, { msgId });
    const r2 = await putEnvelope(pathId, second.envelope, second.signature);
    expect(r2.status).toBe(409);
  });
});

describe("GET /mailbox/:pathId", () => {
  it("returns envelopes addressed to the caller, newest last", async () => {
    const { a, b, pathId } = await activePair();
    // A sends two, B sends one. B should see both A→B, not its own.
    const ct1 = new TextEncoder().encode("a1");
    const e1 = await makeOuterEnvelope(a, pathId, ct1);
    await putEnvelope(pathId, e1.envelope, e1.signature);

    const ct2 = new TextEncoder().encode("a2");
    const e2 = await makeOuterEnvelope(a, pathId, ct2);
    await putEnvelope(pathId, e2.envelope, e2.signature);

    const ct3 = new TextEncoder().encode("b1");
    const e3 = await makeOuterEnvelope(b, pathId, ct3);
    await putEnvelope(pathId, e3.envelope, e3.signature);

    const res = await getMailbox(pathId, b);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { envelopes: Array<{ msg_id: string }>; cursor: string | null };
    const ids = body.envelopes.map((e) => e.msg_id);
    expect(ids).toContain(e1.envelope.msg_id);
    expect(ids).toContain(e2.envelope.msg_id);
    expect(ids).not.toContain(e3.envelope.msg_id);
    expect(body.cursor).toBe(ids[ids.length - 1]);
  });

  it("returns only envelopes strictly newer than `since`", async () => {
    const { a, b, pathId } = await activePair();
    const ct1 = new TextEncoder().encode("first");
    const e1 = await makeOuterEnvelope(a, pathId, ct1);
    await putEnvelope(pathId, e1.envelope, e1.signature);

    const ct2 = new TextEncoder().encode("second");
    const e2 = await makeOuterEnvelope(a, pathId, ct2);
    await putEnvelope(pathId, e2.envelope, e2.signature);

    const res = await getMailbox(pathId, b, e1.envelope.msg_id);
    const body = (await res.json()) as { envelopes: Array<{ msg_id: string }> };
    const ids = body.envelopes.map((e) => e.msg_id);
    expect(ids).toEqual([e2.envelope.msg_id]);
  });

  it("rejects with 401 when the query is not signed by a pair member", async () => {
    const { pathId } = await activePair();
    const impostor = await makeEd25519Identity("nexus-impostor");
    const res = await getMailbox(pathId, impostor);
    expect(res.status).toBe(401);
  });

  it("rejects with 404 when pathId has no pair", async () => {
    const a = await makeEd25519Identity("nexus-alpha");
    const ghost = "nxc_" + "A".repeat(43);
    const res = await getMailbox(ghost, a);
    expect(res.status).toBe(404);
  });
});

describe("POST /mailbox/:pathId/ack", () => {
  it("evicts acked envelopes and reports count", async () => {
    const { a, b, pathId } = await activePair();
    const ct = new TextEncoder().encode("toevict");
    const e = await makeOuterEnvelope(a, pathId, ct);
    await putEnvelope(pathId, e.envelope, e.signature);

    const ack = await ackEnvelopes(pathId, b, [e.envelope.msg_id]);
    expect(ack.status).toBe(200);
    const body = (await ack.json()) as { evicted: number };
    expect(body.evicted).toBe(1);

    // Subsequent GET should return nothing new.
    const res = await getMailbox(pathId, b);
    const gbody = (await res.json()) as { envelopes: Array<unknown> };
    expect(gbody.envelopes).toHaveLength(0);
  });

  it("rejects acks over the batch cap with 400", async () => {
    const { b, pathId } = await activePair();
    const ids = Array.from({ length: 101 }, () => uuidv7());
    const ack = await ackEnvelopes(pathId, b, ids);
    expect(ack.status).toBe(400);
    const body = (await ack.json()) as { error: string; max: number };
    expect(body.error).toBe("too_many_ids");
    expect(body.max).toBe(100);
  });

  it("rejects ack from non-pair-member with 401", async () => {
    const { a, pathId } = await activePair();
    const ct = new TextEncoder().encode("x");
    const e = await makeOuterEnvelope(a, pathId, ct);
    await putEnvelope(pathId, e.envelope, e.signature);

    const impostor = await makeEd25519Identity("nexus-impostor");
    const ack = await ackEnvelopes(pathId, impostor, [e.envelope.msg_id]);
    expect(ack.status).toBe(401);
  });
});
