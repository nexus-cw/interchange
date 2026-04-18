// Key + signing helpers for tests. Uses WebCrypto inside the Workers runtime
// so the exact same crypto primitives the Worker uses are exercised.

export interface Ed25519Half {
  nexus_id: string;
  sig_alg: "ed25519";
  pubkey: string;         // base64url raw 32 bytes
  endpoint: string;       // may be empty
  nonce: string;          // base64url
  ts: string;             // ISO-8601
  self_sig: string;       // base64url 64-byte Ed25519 detached sig
}

export interface Ed25519Identity {
  half: Ed25519Half;
  keyPair: CryptoKeyPair;
}

export async function makeEd25519Half(nexusId: string, endpoint = ""): Promise<Ed25519Half> {
  return (await makeEd25519Identity(nexusId, endpoint)).half;
}

export async function makeEd25519Identity(nexusId: string, endpoint = ""): Promise<Ed25519Identity> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "Ed25519" } as unknown as Algorithm,
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const pubkey = b64urlEncode(rawPub);
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = b64urlEncode(nonceBytes);
  const ts = new Date().toISOString();

  const canonical = canonicalHalf(nexusId, "ed25519", pubkey, endpoint, nonce, ts);
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" } as unknown as Algorithm, keyPair.privateKey, canonical),
  );

  return {
    half: {
      nexus_id: nexusId,
      sig_alg: "ed25519",
      pubkey,
      endpoint,
      nonce,
      ts,
      self_sig: b64urlEncode(sig),
    },
    keyPair,
  };
}

export function canonicalHalf(
  nexusId: string,
  sigAlg: string,
  pubkey: string,
  endpoint: string,
  nonce: string,
  ts: string,
): Uint8Array {
  const s = [
    "v1",
    nexusId,
    sigAlg,
    pubkey,
    endpoint,
    nonce,
    ts,
  ].join("\n");
  return new TextEncoder().encode(s);
}

// Canonical JSON: keys sorted lexicographically, no whitespace, strings
// JSON-escaped via JSON.stringify. Recursive on objects; arrays preserve
// insertion order. Must byte-match what the Worker produces on verify.
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalJson(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k]));
  return "{" + parts.join(",") + "}";
}

export async function signEd25519(kp: CryptoKeyPair, bytes: Uint8Array): Promise<string> {
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" } as unknown as Algorithm, kp.privateKey, bytes),
  );
  return b64urlEncode(sig);
}

export interface OuterEnvelope {
  version: "1";
  msg_id: string;
  ts: string;
  path_id: string;
  ciphertext_sha256: string;
  ciphertext: string;
}

// Build a plausible outer envelope + X-Nexus-Signature. Ciphertext is
// opaque to the Interchange, so tests can use any bytes — we just need
// ciphertext_sha256 to match.
export async function makeOuterEnvelope(
  sender: Ed25519Identity,
  pathId: string,
  ciphertextBytes: Uint8Array,
  opts: { msgId?: string; ts?: string } = {},
): Promise<{ envelope: OuterEnvelope; signature: string }> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ciphertextBytes));
  const envelope: OuterEnvelope = {
    version: "1",
    msg_id: opts.msgId ?? uuidv7(),
    ts: opts.ts ?? new Date().toISOString(),
    path_id: pathId,
    ciphertext_sha256: bytesToHex(digest),
    ciphertext: b64urlEncode(ciphertextBytes),
  };
  const canonical = new TextEncoder().encode(canonicalJson(envelope));
  const signature = await signEd25519(sender.keyPair, canonical);
  return { envelope, signature };
}

export async function signPath(kp: CryptoKeyPair, pathAndQuery: string): Promise<string> {
  return signEd25519(kp, new TextEncoder().encode(pathAndQuery));
}

// UUIDv7-ish: timestamp-ms in first 48 bits, version 7 nibble, variant bits,
// rest random. Good enough for tests; production generator lives in the
// Nexus Frame.
export function uuidv7(): string {
  const now = BigInt(Date.now());
  const rand = crypto.getRandomValues(new Uint8Array(10));
  const bytes = new Uint8Array(16);
  bytes[0] = Number((now >> 40n) & 0xffn);
  bytes[1] = Number((now >> 32n) & 0xffn);
  bytes[2] = Number((now >> 24n) & 0xffn);
  bytes[3] = Number((now >> 16n) & 0xffn);
  bytes[4] = Number((now >> 8n) & 0xffn);
  bytes[5] = Number(now & 0xffn);
  bytes[6] = 0x70 | (rand[0]! & 0x0f);
  bytes[7] = rand[1]!;
  bytes[8] = 0x80 | (rand[2]! & 0x3f);
  bytes[9] = rand[3]!;
  for (let i = 10; i < 16; i++) bytes[i] = rand[i - 6]!;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
