// Tiny base64url + pathId helpers.

export function b64urlDecode(s: string): Uint8Array {
  // Pad to multiple of 4, convert URL alphabet to standard base64.
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const std = s.replaceAll("-", "+").replaceAll("_", "/") + pad;
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a[i]! - b[i]!;
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

// Canonical JSON for signature verification:
// - object keys sorted lexicographically (code-point order)
// - no insignificant whitespace
// - strings emitted via JSON.stringify
// - no trailing newline
// Recursive; arrays preserve insertion order.
//
// The Interchange re-canonicalizes incoming JSON before verifying signatures
// so cross-runtime key-order / whitespace drift does not silently break
// signature checks. Any client whose canonical output does not match this
// function's will fail to authenticate.
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

export async function computePathId(pubA: Uint8Array, pubB: Uint8Array): Promise<string> {
  const [first, second] = compareBytes(pubA, pubB) <= 0 ? [pubA, pubB] : [pubB, pubA];
  const concat = new Uint8Array(first.length + second.length);
  concat.set(first, 0);
  concat.set(second, first.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concat));
  return "nxc_" + b64urlEncode(digest);
}
