import type { Env } from "./worker.js";
import { appendEnvelope, listSince, ackEnvelopes } from "./mailbox.js";
import {
  approvePairRequest,
  createPairRequest,
  denyPairRequest,
  getPairRequestStatus,
  listPairRequests,
} from "./pair.js";

// Mailbox endpoints:
//   PUT  /mailbox/:pathId        — append a signed envelope
//   GET  /mailbox/:pathId?since= — list envelopes newer than `since` (UUIDv7)
//   POST /mailbox/:pathId/ack    — mark envelopes delivered (body: { ids: [...] })
export async function routeMailbox(req: Request, env: Env, url: URL): Promise<Response> {
  const parts = url.pathname.split("/").filter(Boolean);
  // ["mailbox", pathId] or ["mailbox", pathId, "ack"]
  const pathId = parts[1];
  const sub = parts[2];

  if (!pathId || !isValidPathId(pathId)) {
    return json({ error: "invalid_path_id" }, 400);
  }

  if (!sub) {
    if (req.method === "PUT") return appendEnvelope(req, env, pathId);
    if (req.method === "GET") return listSince(req, env, pathId, url);
  } else if (sub === "ack" && req.method === "POST") {
    return ackEnvelopes(req, env, pathId);
  }

  return new Response("not found", { status: 404 });
}

// Staged-approval pair registration:
//   POST /pair/request               — requester submits their half, status=pending
//   GET  /pair/requests?status=...   — owner lists queued requests
//   GET  /pair/requests/:id          — requester polls for decision
//   POST /pair/requests/:id/approve  — owner submits their half, activates pair
//   POST /pair/requests/:id/deny     — owner rejects
export async function routePair(req: Request, env: Env, url: URL): Promise<Response> {
  const parts = url.pathname.split("/").filter(Boolean);
  // parts[0] === "pair"
  const action = parts[1];

  if (action === "request" && req.method === "POST" && parts.length === 2) {
    return createPairRequest(req, env);
  }

  if (action === "requests") {
    if (req.method === "GET" && parts.length === 2) {
      return listPairRequests(req, env, url);
    }
    const requestId = parts[2];
    if (requestId) {
      const sub = parts[3];
      if (!sub && req.method === "GET") {
        return getPairRequestStatus(req, env, requestId);
      }
      if (sub === "approve" && req.method === "POST") {
        return approvePairRequest(req, env, requestId);
      }
      if (sub === "deny" && req.method === "POST") {
        return denyPairRequest(req, env, requestId);
      }
    }
  }

  return new Response("not found", { status: 404 });
}

// pathId format: "nxc_" + base64url(32 bytes). Length check is the cheap filter;
// the real guard is that the mailbox only accepts signed envelopes whose
// signature verifies against the registered pubkeys for this pathId.
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
