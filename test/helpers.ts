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

export async function makeEd25519Half(nexusId: string, endpoint = ""): Promise<Ed25519Half> {
  const kp = (await crypto.subtle.generateKey(
    { name: "Ed25519" } as unknown as Algorithm,
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pubkey = b64urlEncode(rawPub);
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = b64urlEncode(nonceBytes);
  const ts = new Date().toISOString();

  const canonical = canonicalHalf(nexusId, "ed25519", pubkey, endpoint, nonce, ts);
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" } as unknown as Algorithm, kp.privateKey, canonical),
  );

  return {
    nexus_id: nexusId,
    sig_alg: "ed25519",
    pubkey,
    endpoint,
    nonce,
    ts,
    self_sig: b64urlEncode(sig),
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

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
