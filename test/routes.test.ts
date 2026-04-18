import { describe, it, expect, beforeEach } from "vitest";
import { SELF } from "cloudflare:test";
import { applyMigrations } from "./setup.js";

beforeEach(async () => {
  await applyMigrations();
});

describe("routing", () => {
  it("GET /health returns 200 ok", async () => {
    const res = await SELF.fetch("https://example.com/health");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
  });

  it("rejects unknown routes with 404", async () => {
    const res = await SELF.fetch("https://example.com/not-a-thing");
    expect(res.status).toBe(404);
  });

  it("rejects invalid pathId on PUT with 400 invalid_path_id", async () => {
    const res = await SELF.fetch("https://example.com/mailbox/not-a-pathid", {
      method: "PUT",
      body: "{}",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_path_id");
  });

  it("accepts well-formed pathId shape (routes past validation)", async () => {
    const valid = "nxc_" + "A".repeat(43);
    const res = await SELF.fetch(`https://example.com/mailbox/${valid}`, {
      method: "PUT",
      body: "{}",
    });
    // Validation passes; downstream returns 501 until the append handler lands.
    expect(res.status).not.toBe(400);
  });
});
