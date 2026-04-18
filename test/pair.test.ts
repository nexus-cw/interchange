import { describe, it, expect, beforeEach } from "vitest";
import { SELF, env } from "cloudflare:test";
import { applyMigrations } from "./setup.js";
import { makeEd25519Half } from "./helpers.js";

beforeEach(async () => {
  await applyMigrations();
});

async function postRequest(body: unknown) {
  return SELF.fetch("https://example.com/pair/request", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function postApprove(requestId: string, body: unknown) {
  return SELF.fetch(`https://example.com/pair/requests/${requestId}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function postDeny(requestId: string) {
  return SELF.fetch(`https://example.com/pair/requests/${requestId}/deny`, {
    method: "POST",
  });
}

async function getStatus(requestId: string) {
  return SELF.fetch(`https://example.com/pair/requests/${requestId}`);
}

async function listPending() {
  return SELF.fetch("https://example.com/pair/requests?status=pending");
}

describe("POST /pair/request", () => {
  it("stages a pending request and returns a request_id", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const res = await postRequest({ target_nexus_id: "keel-nexus", requester });
    expect(res.status).toBe(201);
    const json = (await res.json()) as { request_id: string; status: string };
    expect(json.status).toBe("pending");
    expect(json.request_id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("rejects a tampered self_sig with bad_self_sig", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const tampered = { ...requester, nexus_id: "nexus-evil" };
    const res = await postRequest({ target_nexus_id: "keel-nexus", requester: tampered });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("bad_self_sig");
  });

  it("rejects stale timestamps outside the replay window", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const stale = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const res = await postRequest({
      target_nexus_id: "keel-nexus",
      requester: { ...requester, ts: stale },
    });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("ts_out_of_window");
  });

  it("requires target_nexus_id", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const res = await postRequest({ requester });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("missing_target");
  });
});

describe("GET /pair/requests?status=pending", () => {
  it("lists pending requests with requester identity visible", async () => {
    const requester = await makeEd25519Half("nexus-alpha", "https://alpha.example");
    await postRequest({ target_nexus_id: "keel-nexus", requester });
    const res = await listPending();
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      requests: Array<{
        request_id: string;
        status: string;
        requester: { nexus_id: string; pubkey: string; endpoint: string };
      }>;
    };
    expect(json.requests).toHaveLength(1);
    expect(json.requests[0]!.status).toBe("pending");
    expect(json.requests[0]!.requester.nexus_id).toBe("nexus-alpha");
    expect(json.requests[0]!.requester.endpoint).toBe("https://alpha.example");
  });
});

describe("POST /pair/requests/:id/approve", () => {
  it("activates the pair and returns a path_id", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const reqRes = await postRequest({ target_nexus_id: "keel-nexus", requester });
    const { request_id } = (await reqRes.json()) as { request_id: string };

    const owner = await makeEd25519Half("keel-nexus");
    const res = await postApprove(request_id, { owner });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { status: string; path_id: string };
    expect(json.status).toBe("approved");
    expect(json.path_id).toMatch(/^nxc_[A-Za-z0-9_-]{42,44}$/);

    const pair = await (env as { DB: D1Database }).DB
      .prepare("SELECT path_id, sig_alg_a, sig_alg_b FROM pairs WHERE path_id = ?")
      .bind(json.path_id)
      .first();
    expect(pair).not.toBeNull();
  });

  it("rejects cross-algorithm approval with sig_alg_mismatch", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const reqRes = await postRequest({ target_nexus_id: "keel-nexus", requester });
    const { request_id } = (await reqRes.json()) as { request_id: string };

    const owner = await makeEd25519Half("keel-nexus");
    const res = await postApprove(request_id, { owner: { ...owner, sig_alg: "p256" } });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("sig_alg_mismatch");
  });

  it("rejects a tampered owner self_sig", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const reqRes = await postRequest({ target_nexus_id: "keel-nexus", requester });
    const { request_id } = (await reqRes.json()) as { request_id: string };

    const owner = await makeEd25519Half("keel-nexus");
    const res = await postApprove(request_id, { owner: { ...owner, nexus_id: "keel-evil" } });
    expect(res.status).toBe(400);
    const json = (await res.json()) as { error: string };
    expect(json.error).toBe("bad_self_sig");
  });

  it("returns 404 for unknown request_id", async () => {
    const owner = await makeEd25519Half("keel-nexus");
    const res = await postApprove("00000000-0000-0000-0000-000000000000", { owner });
    expect(res.status).toBe(404);
  });

  it("rejects a second approve on the same request with 409", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const reqRes = await postRequest({ target_nexus_id: "keel-nexus", requester });
    const { request_id } = (await reqRes.json()) as { request_id: string };

    const owner1 = await makeEd25519Half("keel-nexus");
    const first = await postApprove(request_id, { owner: owner1 });
    expect(first.status).toBe(200);

    const owner2 = await makeEd25519Half("keel-nexus");
    const second = await postApprove(request_id, { owner: owner2 });
    expect(second.status).toBe(409);
  });
});

describe("POST /pair/requests/:id/deny", () => {
  it("marks the request denied and blocks later approval", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const reqRes = await postRequest({ target_nexus_id: "keel-nexus", requester });
    const { request_id } = (await reqRes.json()) as { request_id: string };

    const deny = await postDeny(request_id);
    expect(deny.status).toBe(200);
    const denyJson = (await deny.json()) as { status: string };
    expect(denyJson.status).toBe("denied");

    const owner = await makeEd25519Half("keel-nexus");
    const approve = await postApprove(request_id, { owner });
    expect(approve.status).toBe(409);
  });
});

describe("GET /pair/requests/:id", () => {
  it("returns pending then approved with path_id after owner acts", async () => {
    const requester = await makeEd25519Half("nexus-alpha");
    const reqRes = await postRequest({ target_nexus_id: "keel-nexus", requester });
    const { request_id } = (await reqRes.json()) as { request_id: string };

    const poll1 = await getStatus(request_id);
    expect(poll1.status).toBe(200);
    const j1 = (await poll1.json()) as { status: string; path_id?: string };
    expect(j1.status).toBe("pending");
    expect(j1.path_id).toBeUndefined();

    const owner = await makeEd25519Half("keel-nexus");
    await postApprove(request_id, { owner });

    const poll2 = await getStatus(request_id);
    const j2 = (await poll2.json()) as { status: string; path_id: string };
    expect(j2.status).toBe("approved");
    expect(j2.path_id).toMatch(/^nxc_[A-Za-z0-9_-]{42,44}$/);
  });

  it("returns 404 for unknown request_id", async () => {
    const res = await getStatus("00000000-0000-0000-0000-000000000000");
    expect(res.status).toBe(404);
  });
});
