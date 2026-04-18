import type { Env } from "./worker.js";

// Mailbox endpoints:
//   PUT  /mailbox/:pathId        — append a signed envelope
//   GET  /mailbox/:pathId?since= — list envelopes newer than `since` (UUIDv7)
//   POST /mailbox/:pathId/ack    — mark envelopes delivered (body: { ids: [...] })
export async function routeMailbox(req: Request, env: Env, url: URL): Promise<Response> {
  const parts = url.pathname.split("/").filter(Boolean);
  // ["mailbox", pathId, ...]
  const pathId = parts[1];
  if (!pathId || !isValidPathId(pathId)) {
    return json({ error: "invalid_path_id" }, 400);
  }

  const id = env.MAILBOX.idFromName(pathId);
  const stub = env.MAILBOX.get(id);
  return stub.fetch(req);
}

// Pairing endpoints:
//   POST /pair/register — register a pair's public keys + sig_alg so the
//                          Interchange can verify PUTs to their pathId.
export async function routePair(req: Request, _env: Env, url: URL): Promise<Response> {
  const parts = url.pathname.split("/").filter(Boolean);
  const action = parts[1];
  if (action === "register" && req.method === "POST") {
    return json({ error: "not_implemented" }, 501);
  }
  return new Response("not found", { status: 404 });
}

// pathId format: "nxc_" + base64url(32 bytes). Length check is the cheap filter;
// the real guard is that the DO only accepts signed envelopes whose signature
// verifies against the registered pubkeys for this pathId.
function isValidPathId(s: string): boolean {
  if (!s.startsWith("nxc_")) return false;
  const body = s.slice(4);
  if (body.length < 42 || body.length > 44) return false;
  return /^[A-Za-z0-9_-]+$/.test(body);
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
