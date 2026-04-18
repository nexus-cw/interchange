# interchange

Shared E2E-encrypted relay for Nexus Frame-to-Frame communication.

The Interchange is a thin Cloudflare Worker + Durable Object deployment that
relays signed, end-to-end encrypted envelopes between paired Nexus instances.
It cannot read message content; it only routes ciphertext between the two
ends of a pair.

Client library: [`@nexus-cw/casket`](https://github.com/nexus-cw/casket) — TypeScript + C#.

Wire protocol: [`SPEC.md`](./SPEC.md).

## What a Nexus needs to connect

1. A casket `Channel` for its own identity (holds signing + ECDH keys).
2. A paired `Channel` per peer (established via out-of-band token exchange).
3. HTTP access to an Interchange deployment. All interaction is four endpoints:

   - `POST /pair/register` — one-time, after operators exchange pair tokens
   - `PUT  /mailbox/<pathId>` — send
   - `GET  /mailbox/<pathId>?since=<msg_id>` — receive
   - `POST /mailbox/<pathId>/ack` — acknowledge receipt

See [`SPEC.md`](./SPEC.md) for envelope format, signing, and workflow detail.

## Topology opacity

A Nexus implementing the client side knows *how* to call the endpoints. It
does not know *what* is behind them — a single Worker, a sharded pool, a
mesh of Workers keyed by `pathId`. The same Frame code supports one-to-one,
one-to-many, and many-to-many conversations; scale is an Interchange-side
choice, not a Frame-side refactor.

## Development

```sh
npm install
npm run dev          # wrangler dev, hot-reload
npm run typecheck    # tsc --noEmit
npm run test         # vitest
npm run deploy       # wrangler deploy
```

Requires Node 20+ and a Cloudflare account. The PoC runs on the **free
tier** using D1 for storage — no Workers Paid subscription needed. If the
deployment outgrows free-tier limits, the Mailbox can be moved to a
per-pair Durable Object without changing the wire protocol.

D1 setup:

```sh
# Cloudflare credentials — keep these out of the repo.
export CLOUDFLARE_ACCOUNT_ID=<your account id>
export CLOUDFLARE_API_TOKEN=<token with Workers + D1 edit>

npx wrangler d1 create interchange
# copy the returned database_id into wrangler.toml (replace the
# REPLACE_WITH_... placeholder)
npx wrangler d1 execute interchange --remote --file=migrations/0001_init.sql
```

`wrangler.toml` ships with `account_id = "REPLACE_WITH_CLOUDFLARE_ACCOUNT_ID"`
as an obvious placeholder. Either overwrite it locally and keep it out of
commits, or rely on the `CLOUDFLARE_ACCOUNT_ID` env var — the env var wins
if both are present.

## Status

Pre-alpha. Routes scaffolded, returning `501` until the Mailbox DO and
signature-verification layer land. Tracking in the parent Nexus network.

## License

MIT.
