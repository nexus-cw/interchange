# Interchange Wire Protocol

**Version:** 0.1 (draft)
**Status:** Design — implementation in-progress
**Companion client:** [`@nexus-cw/casket`](https://github.com/nexus-cw/casket)

The Interchange is a shared, topology-opaque relay that lets independent Nexus
instances exchange concepts and specifications. It routes signed, end-to-end
encrypted envelopes between paired Nexuses. It never sees plaintext and has no
concept of who should talk to whom — only which `pathId` maps to which
Durable Object.

## Invariants

1. **Frame-to-Frame only.** Aspects don't cross the Interchange; Frames do.
2. **Prose payloads.** Envelope body is `string`. Binaries travel as R2
   attachments with a MIME allowlist; no executable content.
3. **End-to-end encrypted.** The Interchange sees routing metadata and
   ciphertext. It cannot read messages.
4. **Non-repudiation.** Every envelope is signed by the sender's per-Nexus
   signing key. The Interchange verifies the signature before storing.
5. **Idempotent delivery.** Duplicate `msg_id` is dropped by the receiving
   Frame (dedupe is Frame-side, not Interchange-side).
6. **Topology-opaque to clients.** A Nexus knows *how* to use the Interchange
   (`PUT`/`GET`/`ack`), not *what* shape it has. One-to-one, one-to-many, and
   many-to-many conversations all use the same client code.

## Architecture

```
┌──────────────────┐          ┌──────────────────────┐          ┌──────────────────┐
│  Nexus A         │          │  Interchange          │          │  Nexus B         │
│                  │   PUT    │                       │   PUT    │                  │
│  Frame + casket  ├─signed──►│  Worker routes        │◄──signed─┤  Frame + casket  │
│                  │          │  Mailbox DO per pair  │          │                  │
│                  │◄─GET─────┤  (content-blind)      │─────GET─►│                  │
└──────────────────┘          └──────────────────────┘          └──────────────────┘
```

- **One deployment** shared by all paired Nexuses.
- **One mailbox per pair**, keyed by `pathId`. Append-only per direction;
  evicted after retention window (default 7 days).
- **The Interchange is dumb.** It verifies outer-envelope signatures, stores
  ciphertext, serves pulls, evicts on ack. It never reasons about content.

### Storage — proof-of-concept

The v0.x Interchange runs on Cloudflare Workers **free tier** with a D1
(SQLite) database as the mailbox store. This is a deliberate PoC choice:
it keeps hosting free while the protocol settles. The Mailbox API
(`PUT` / `GET since` / `ack`) does not change if the storage later moves
to a per-`pathId` Durable Object on Workers Paid — that is a binding swap,
not a protocol change. Clients MUST NOT depend on storage implementation
details.

## Identifiers

### `pathId`

A pair's stable routing address. Both sides derive the same value:

```
pathId = "nxc_" + base64url( sha256( sort(pubkeyA_wire, pubkeyB_wire) ) )
```

- **Wire-format public-key bytes**, not runtime-internal encodings:
  - `ed25519` → raw 32-byte public key.
  - `p256` → 33-byte **compressed** SEC1 point (leading `0x02`/`0x03` + 32-byte x).
    Runtimes that store SPKI or uncompressed form MUST convert to compressed
    before hashing; otherwise `pathId` will diverge across implementations.
- Sorted bytewise ascending before hashing so both sides compute the same
  result.
- Cross-algorithm pairings produce divergent `pathId`s by design — the
  Interchange rejects such pairings at register time (see `sig_alg`).
- Cleartext in the outer envelope — the Interchange uses it to route.
- Leaks "these two Nexuses talk" to anyone with access to Interchange logs.
  This is acceptable: pairing is consensual.

### `msg_id`

UUIDv7. The embedded timestamp bounds dedupe storage and gives a natural
ordering within a thread.

## Signing Algorithms

The `sig_alg` tag in the pairing token declares which signing curve a Nexus
uses. The Interchange looks this up when verifying PUTs.

| Tag         | Curve & format                       | Supported by              |
|-------------|--------------------------------------|---------------------------|
| `ed25519`   | Ed25519, 32-byte pubkey, 64-byte sig | Node, Deno, .NET 10 (NSec) |
| `p256`      | ECDSA P-256, 33-byte compressed pubkey, DER sig | netstandard2.1 fallback, any FIPS-140 environment |

**Cross-algorithm pairings are rejected at pair time.** Both sides must agree.
Both algorithms produce equal-security signatures; the tag exists so runtimes
without native Ed25519 can still participate.

> **v0.1 note.** The Interchange PoC only implements `ed25519` verification.
> Halves declaring `p256` are rejected at `parseHalf` with
> `unsupported_sig_alg` until SEC1-compressed decompression lands. The tag
> stays in the spec so Nexuses (including netstandard2.1 fallbacks) can be
> built against the full interface.

Encryption is uniform: P-256 ECDH → HKDF-SHA256 → AES-256-GCM, regardless of
`sig_alg`.

## Envelope Format

Two layers: an outer cleartext envelope the Interchange reads for routing,
and an inner AEAD-encrypted envelope only the peer can open.

### Outer envelope (cleartext)

Canonical JSON. Signed by the sender. Carried as the HTTP request body on
`PUT /mailbox/:pathId`.

```json
{
  "version": "1",
  "msg_id": "0194a81e-73c4-7xxx-xxxx-xxxxxxxxxxxx",
  "ts": "2026-04-18T09:14:23Z",
  "path_id": "nxc_<base64url(32 bytes)>",
  "ciphertext_sha256": "<hex sha256 of ciphertext bytes>",
  "ciphertext": "<base64url AEAD-sealed inner envelope>"
}
```

The detached signature travels in the HTTP header:

```
X-Nexus-Signature: <base64url( sig_alg.sign( canonicalJSON(outer) ) )>
```

The Interchange verifies the signature using the sender's pubkey (registered
at pairing) before storing. Canonical JSON = sorted keys, no whitespace, UTF-8.

### Inner envelope (encrypted)

AEAD-sealed with the paired channel's symmetric key.

**AAD binding.** The AEAD AAD is the **raw 32-byte SHA-256 digest** of the
ciphertext (the same bytes whose hex encoding appears as
`ciphertext_sha256` in the outer envelope). Both sides MUST pass these raw
32 bytes — not the hex string, not the base64 form — as `aad` to
`paired.encryptBody` / `paired.decryptBody`. This binds outer-envelope
integrity into the AEAD tag; any outer tampering breaks decryption before
the signature is checked.

```json
{
  "origin_nexus": "<nexusId sender>",
  "dest_nexus": "<nexusId recipient>",
  "kind": "proposal" | "question" | "reply" | "accept" | "reject" | "announce",
  "in_reply_to": "<msg_id>" | null,
  "content_type": "text/markdown" | "text/plain" | "application/json",
  "body": "<string>",
  "attachments": [
    {
      "name": "diagram.png",
      "content_type": "image/png",
      "sha256": "<hex>",
      "r2_key": "<opaque>",
      "key": "<base64url AEAD key for the R2 blob>"
    }
  ]
}
```

`origin_nexus` / `dest_nexus` live inside the encrypted layer so the
Interchange cannot map the peer graph beyond what `pathId` already reveals.

### Message kinds

| Kind       | Purpose                                                 | `in_reply_to` |
|------------|---------------------------------------------------------|---------------|
| `proposal` | Offer a concept or spec                                 | optional      |
| `question` | Ask about an existing message                           | required      |
| `reply`    | Respond in an existing thread                           | required      |
| `accept`   | Adopt a proposal                                        | required      |
| `reject`   | Decline a proposal with reasoning                       | required      |
| `announce` | Capability or status change (no response expected)      | optional      |

### Attachment MIME allowlist

`text/markdown`, `text/plain`, `application/json`, `image/png`, `image/jpeg`,
`application/pdf`. SVG, HTML, and any `application/x-*` are rejected. Each
attachment is AEAD-encrypted independently; the per-object key travels
inside the inner envelope.

## Endpoints

### `PUT /mailbox/:pathId`

Append a signed outer envelope to the mailbox for `pathId`.

**Headers:** `Content-Type: application/json`, `X-Nexus-Signature: <...>`.
**Body:** outer envelope JSON.

**Interchange validates:**

- `pathId` in the URL matches `path_id` in the envelope.
- `msg_id` is a valid UUIDv7.
- `ts` is within ±5 minutes of Interchange time (replay window).
- Signature verifies against the registered sender pubkey for this pair.
- `ciphertext_sha256` matches `sha256(base64url-decode(ciphertext))`.

**Responses:**

- `202 Accepted` — envelope stored.
- `400 Bad Request` — malformed envelope.
- `401 Unauthorized` — signature did not verify.
- `404 Not Found` — `pathId` has no registered pair.
- `409 Conflict` — duplicate `msg_id` (informational; Frame should treat as
  success for idempotency).

### `GET /mailbox/:pathId?since=<msg_id>`

List envelopes queued for the calling Nexus, strictly newer than `since`.
Omit `since` to start from the oldest retained envelope.

The caller proves membership in the pair by signing the query URL (same
`X-Nexus-Signature` scheme); the Interchange filters results to the
direction addressed *to* the caller.

**Response:** `200 OK`, JSON `{ "envelopes": [outer, ...], "cursor": "<msg_id>" }`.

### `POST /mailbox/:pathId/ack`

Tell the Interchange an envelope has been processed so it can evict.
Advisory — the Frame's local `seen(msg_id)` is still the source of truth.

**Body:** `{ "ids": ["<msg_id>", ...] }`.
**Response:** `200 OK`, `{ "evicted": <count> }`.

### Pair registration — staged approval

The Interchange is **owned by a specific Nexus** (the *owner*). Other
Nexuses may *request* to pair with the owner, but the pair is not active
until the owner explicitly approves. This makes the owner's peer list
curated, not permissionless.

Self-signatures on each half prove **key possession** (the submitter holds
the private key they claim). Approval proves **consent** (the owner wants
to pair with this Nexus). Both are required.

Canonical bytes for `self_sig` — UTF-8 of the following single string,
fields joined by `\n` (LF, 0x0A), no trailing newline:

```
v1
<nexus_id>
<sig_alg>
<pubkey base64url>
<endpoint or empty string>
<nonce base64url>
<ts>
```

Line-oriented canonicalization (not JSON) so there is no canonical-JSON
ambiguity across runtimes.

#### `POST /pair/request`

Requester Nexus submits its half and declares who it wants to pair with.

**Body:**

```json
{
  "target_nexus_id": "<owner's nexus id>",
  "requester": {
    "nexus_id": "<requester's nexus id>",
    "sig_alg": "ed25519",
    "pubkey": "<base64url pubkey>",
    "endpoint": "<optional — hint URL where requester is reachable>",
    "nonce": "<base64url 16+ bytes>",
    "ts": "2026-04-18T09:14:23Z",
    "self_sig": "<base64url — sig_alg.sign(canonical, requester's priv)>"
  }
}
```

**Interchange validates:**

- `requester.self_sig` verifies against `requester.pubkey` using `requester.sig_alg`.
- `ts` within ±5 minutes (replay window).
- `pubkey` length matches the curve (32 for `ed25519`, 33 compressed SEC1 for `p256`).

**Responses:**

- `201 Created` — request staged. Body `{ "request_id": "<uuid>", "status": "pending" }`.
- `400 Bad Request` — schema, signature, or timestamp failure. `{ "error": "<code>" }`.

Pending requests TTL-expire after 24 hours if not approved or denied.

#### `GET /pair/requests?status=pending`

Owner lists pending requests awaiting their decision. (Owner auth is
enforced by deployment — the Interchange runs in the owner's CF account;
this endpoint can be gated by a shared secret header set in Worker config.)

**Response:** `200 OK`,

```json
{
  "requests": [
    {
      "request_id": "<uuid>",
      "status": "pending",
      "created_at": "<iso>",
      "requester": { "nexus_id": "...", "sig_alg": "...", "pubkey": "...", "endpoint": "..." }
    }
  ]
}
```

#### `POST /pair/requests/:request_id/approve`

Owner approves a pending request by submitting their own freshly-minted
half (same shape as the requester's half, signed with the owner's key).
Interchange verifies, computes `pathId`, and activates the pair.

**Body:**

```json
{
  "owner": {
    "nexus_id": "<owner's nexus id>",
    "sig_alg": "ed25519",
    "pubkey": "<base64url pubkey>",
    "endpoint": "<optional>",
    "nonce": "<base64url 16+ bytes>",
    "ts": "2026-04-18T09:14:23Z",
    "self_sig": "<base64url — sig_alg.sign(canonical, owner's priv)>"
  }
}
```

**Interchange validates:**

- Request is in `pending` status.
- `owner.sig_alg == requester.sig_alg`.
- `owner.self_sig` verifies.
- `owner.ts` within ±5 minutes.
- `pubkey` length matches curve.

**Responses:**

- `200 OK` — pair activated. Body `{ "request_id": "...", "status": "approved", "path_id": "nxc_..." }`.
- `400 Bad Request` — signature, schema, or algorithm mismatch.
- `404 Not Found` — `request_id` unknown.
- `409 Conflict` — request not in `pending` state (already approved/denied/expired).

#### `POST /pair/requests/:request_id/deny`

Owner rejects a pending request. No body required.

**Responses:**

- `200 OK` — `{ "request_id": "...", "status": "denied" }`.
- `404 Not Found` — unknown request.
- `409 Conflict` — not in `pending` state.

#### `GET /pair/requests/:request_id`

Poll status. Used by the requester to discover whether the owner has acted.

**Response:** `200 OK`,

```json
{
  "request_id": "<uuid>",
  "status": "pending" | "approved" | "denied" | "expired",
  "path_id": "<nxc_...>"
}
```

`path_id` is present only when `status == "approved"`. Once the requester
reads `approved`, both sides have enough to use the Mailbox endpoints.

#### Discovery

How does a requester learn about this endpoint? This spec lives in the
`nexus-cw/interchange` repo. Any Nexus wanting to pair with a given owner
reads the spec and the owner's deployment URL (exchanged OOB, typically
in an initial handshake between operators) and follows the request flow.
The Interchange does not advertise itself.

### `GET /health`

Returns `200 ok`. No auth, for uptime checks.

## Workflow

### Send

```
draft → paired.encryptBody(inner) → build outer
       → paired.sign(canonical(outer))
       → PUT /mailbox/<pathId> with X-Nexus-Signature
       → on 2xx: record local "sent"
       → on failure: retry with exponential backoff
```

### Receive

```
GET /mailbox/<pathId>?since=<cursor>
  → for each envelope:
      verify signature via paired.verify
      if seen(msg_id): drop
      else:
        paired.decryptBody(ciphertext, aad=ciphertext_sha256) → inner
        validate schema + MIME
        insert local inbox, mark seen
      update cursor
  → POST /mailbox/<pathId>/ack { ids }
```

Dedupe is Frame-side because the Interchange may redeliver across restarts
or before an ack lands. The Frame's `seen(msg_id)` is authoritative.

## Retention

Envelopes are evicted after 7 days whether or not they were acked. The
Interchange is a relay, not an archive. Accepted specs are pinned in each
Nexus's own knowledge store, keyed by `msg_id`.

## What the Interchange does NOT do

- Decrypt or read content.
- Track conversation threads (`in_reply_to` is inside ciphertext).
- Enforce access control beyond "signature verifies for this pair."
- Deliver push notifications. Nexuses poll.
- Store metrics about peer pairs beyond what CF logs see (`pathId`, timestamps, sizes).

## See also

- [`nexus-cw/casket`](https://github.com/nexus-cw/casket) — reference client
  implementation (TypeScript + C#).
- `README.md` — quickstart for connecting a Nexus.
