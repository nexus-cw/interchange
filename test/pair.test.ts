import { describe, it, expect, beforeEach } from "vitest";
import { SELF, env } from "cloudflare:test";
import { applyMigrations } from "./setup.js";

beforeEach(async () => {
  await applyMigrations();
});

// Minimal registration bodies use Ed25519 32-byte pubkeys, base64url-encoded.
// The Worker will derive pathId = "nxc_" + base64url(sha256(sort(pubA, pubB))).
// For the first RED test we don't care about signatures yet — spec layers
// self-signing in later; we're verifying the storage + pathId shape here.

const PUBKEY_A_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 zero bytes
const PUBKEY_B_B64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"; // 32 bytes != A

describe("POST /pair/register", () => {
  it("registers a pair and returns a pathId", async () => {
    const body = {
      a: { sig_alg: "ed25519", pubkey: PUBKEY_A_B64 },
      b: { sig_alg: "ed25519", pubkey: PUBKEY_B_B64 },
    };
    const res = await SELF.fetch("https://example.com/pair/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(201);
    const json = (await res.json()) as { path_id: string };
    expect(json.path_id).toMatch(/^nxc_[A-Za-z0-9_-]{42,44}$/);
  });

  it("rejects cross-algorithm pairings with 400", async () => {
    const body = {
      a: { sig_alg: "ed25519", pubkey: PUBKEY_A_B64 },
      b: { sig_alg: "p256", pubkey: PUBKEY_B_B64 },
    };
    const res = await SELF.fetch("https://example.com/pair/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("sig_alg_mismatch");
  });

  it("computes the same pathId regardless of input order", async () => {
    // Distinct pair, but same two pubkeys swapped — pathId must match.
    const ab = {
      a: { sig_alg: "ed25519", pubkey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA" },
      b: { sig_alg: "ed25519", pubkey: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA" },
    };
    const ba = { a: ab.b, b: ab.a };
    const r1 = await SELF.fetch("https://example.com/pair/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(ab),
    });
    // Second call is idempotent on the same pathId — accepting 201 or 409.
    const r2 = await SELF.fetch("https://example.com/pair/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(ba),
    });
    const j1 = (await r1.json()) as { path_id: string };
    const j2 = (await r2.json()) as { path_id?: string; error?: string };
    expect(r1.status).toBe(201);
    expect([201, 409]).toContain(r2.status);
    const returnedPath = j2.path_id ?? j1.path_id;
    expect(returnedPath).toBe(j1.path_id);
  });

  it("persists the pair row so it can be looked up by pathId", async () => {
    const body = {
      a: { sig_alg: "ed25519", pubkey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA" },
      b: { sig_alg: "ed25519", pubkey: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA" },
    };
    const res = await SELF.fetch("https://example.com/pair/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
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
