// D1-backed Mailbox operations. Free-tier PoC storage — strong consistency,
// SQL-shaped. Same append / list-since / ack shape the DO version would
// expose, so the Paid-tier upgrade to a per-pair DO is a swap, not a
// protocol change.
//
// The Interchange is content-blind: it stores the outer (cleartext-routing,
// AEAD-inner) envelope verbatim. It does not decrypt.

import type { Env } from "./worker.js";

export async function appendEnvelope(_req: Request, _env: Env, _pathId: string): Promise<Response> {
  return json({ error: "not_implemented" }, 501);
}

export async function listSince(_req: Request, _env: Env, _pathId: string, _url: URL): Promise<Response> {
  return json({ error: "not_implemented" }, 501);
}

export async function ackEnvelopes(_req: Request, _env: Env, _pathId: string): Promise<Response> {
  return json({ error: "not_implemented" }, 501);
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
