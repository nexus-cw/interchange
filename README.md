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

Requires Node 20+ and a Cloudflare account with Workers Paid (for Durable Objects).

## Status

Pre-alpha. Routes scaffolded, returning `501` until the Mailbox DO and
signature-verification layer land. Tracking in the parent Nexus network.

## License

MIT.
