import { describe, it, expect, beforeEach } from "vitest";
import { SELF, env } from "cloudflare:test";
import { applyMigrations } from "./setup.js";
import { makeEd25519Half } from "./helpers.js";

beforeEach(async () => {
  await applyMigrations();
});

async function postPair(a: unknown, b: unknown) {
  return SELF.fetch("https://example.com/pair/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ a, b }),
  });
}

describe("POST /pair/register", () => {
  it("registers a pair with valid self-sigs and returns a pathId", async () => {
    const a = await makeEd25519Half("nexus-alpha");
    const b = await makeEd25519Half("nexus-beta");
    const res = await postPair(a, b);
    expect(res.status).toBe(201);
    const json = (await res.json()) as { path_id: string };
    expect(json.path_id).toMatch(/^nxc_[A-Za-z0-9_-]{42,44}$/);
  });

  it("rejects cross-algorithm pairings with 400", async () => {
    const a = await makeEd25519Half("nexus-alpha");
    const b = await makeEd25519Half("nexus-beta");
    const res = await postPair(a, { ...b, sig_alg: "p256" });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("sig_alg_mismatch");
  });

  it("rejects a half whose self_sig does not verify", async () => {
    const a = await makeEd25519Half("nexus-alpha");
    const b = await makeEd25519Half("nexus-beta");
    // Tamper with nexus_id after signing — signature no longer matches the
    // canonical bytes the Interchange will reconstruct.
    const tamperedA = { ...a, nexus_id: "nexus-evil" };
    const res = await postPair(tamperedA, b);
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("bad_self_sig");
  });

  it("rejects stale timestamps outside the replay window", async () => {
    const a = await makeEd25519Half("nexus-alpha");
    const b = await makeEd25519Half("nexus-beta");
    // Move A's ts 10 minutes into the past — Worker window is ±5.
    const stale = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const staleA = { ...a, ts: stale };
    const res = await postPair(staleA, b);
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("ts_out_of_window");
  });

  it("computes the same pathId regardless of input order", async () => {
    const a = await makeEd25519Half("nexus-alpha");
    const b = await makeEd25519Half("nexus-beta");
    const r1 = await postPair(a, b);
    const r2 = await postPair(b, a);
    const j1 = (await r1.json()) as { path_id: string };
    const j2 = (await r2.json()) as { path_id?: string; error?: string };
    expect(r1.status).toBe(201);
    expect([201, 409]).toContain(r2.status);
    const returnedPath = j2.path_id ?? j1.path_id;
    expect(returnedPath).toBe(j1.path_id);
  });

  it("persists the pair row so it can be looked up by pathId", async () => {
    const a = await makeEd25519Half("nexus-alpha");
    const b = await makeEd25519Half("nexus-beta");
    const res = await postPair(a, b);
    const { path_id } = (await res.json()) as { path_id: string };
    const row = await (env as { DB: D1Database }).DB
      .prepare("SELECT path_id, sig_alg_a, sig_alg_b FROM pairs WHERE path_id = ?")
      .bind(path_id)
      .first();
    expect(row).not.toBeNull();
    expect((row as { sig_alg_a: string }).sig_alg_a).toBe("ed25519");
    expect((row as { sig_alg_b: string }).sig_alg_b).toBe("ed25519");
  });
});
