// Per-pair Durable Object. Stores envelopes keyed by msg_id (UUIDv7 so time-
// ordered). Content-blind: it sees the outer cleartext envelope (routing +
// ciphertext) but never the inner plaintext. Dedupe is the caller's job.

export class Mailbox implements DurableObject {
  // @ts-expect-error — state wiring lands with the first real endpoint.
  private state: DurableObjectState;

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const method = req.method;
    const path = url.pathname;

    // PUT /mailbox/:pathId
    if (method === "PUT" && /^\/mailbox\/[^/]+$/.test(path)) {
      return json({ error: "not_implemented" }, 501);
    }

    // GET /mailbox/:pathId?since=
    if (method === "GET" && /^\/mailbox\/[^/]+$/.test(path)) {
      return json({ error: "not_implemented" }, 501);
    }

    // POST /mailbox/:pathId/ack
    if (method === "POST" && /^\/mailbox\/[^/]+\/ack$/.test(path)) {
      return json({ error: "not_implemented" }, 501);
    }

    return new Response("not found", { status: 404 });
  }
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
