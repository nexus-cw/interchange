import { routeMailbox, routePair } from "./routes.js";

export interface Env {
  DB: D1Database;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/health") {
      return new Response("ok", { status: 200 });
    }

    if (path.startsWith("/mailbox/")) {
      return routeMailbox(req, env, url);
    }

    if (path.startsWith("/pair/")) {
      return routePair(req, env, url);
    }

    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
