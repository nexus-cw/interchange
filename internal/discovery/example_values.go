package discovery

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// All example values are computed deterministically from fixed inputs
// at process startup. Cheap (well under 1ms) — runs once per main.go's
// discovery.Handler() construction, then served on every well-known hit.

const (
	// Test seeds — 32 bytes of 0x00 and 0x01 respectively. Implementers
	// can reproduce by passing these to ed25519.NewKeyFromSeed.
	aliceSeedHex = "0000000000000000000000000000000000000000000000000000000000000000"
	bobSeedHex   = "0101010101010101010101010101010101010101010101010101010101010101"

	exampleNexusID  = "alice-nexus"
	exampleEndpoint = "https://alice.example.org:10000"
	// Fixed nonce + ts so the example is stable. Real implementations
	// MUST use fresh random nonces and current timestamps.
	exampleNonce = "AAECAwQFBgcICQoLDA0ODw"     // 16 bytes 0x00..0x0F base64url
	exampleTs    = "2026-04-30T00:00:00Z"
)

var (
	alicePubB64u, alicePrivKey = mustEdKey(aliceSeedHex)
	bobPubB64u, _              = mustEdKey(bobSeedHex)

	examplePreimage    = buildPreimage()
	examplePreimageSig = signPreimage(alicePrivKey, examplePreimage)

	exampleOuterCanonical    = buildExampleOuter()
	exampleOuterWireHex      = hex.EncodeToString([]byte(exampleOuterCanonical))
	exampleOuterSig          = signCanonical(alicePrivKey, exampleOuterCanonical)
	exampleCiphertextSHA256Hex = computeCiphertextSHA256()

	examplePathID = derivePathID(alicePubB64u, bobPubB64u)
)

func mustEdKey(seedHex string) (string, ed25519.PrivateKey) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		panic("discovery example: bad seed hex")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return base64.RawURLEncoding.EncodeToString(pub), priv
}

// buildPreimage produces the line-oriented UTF-8 self-sig preimage per
// the discovery doc's pairing.self_sig_canonical: "v1\n<nexus_id>\n
// <sig_alg>\n<pubkey b64u>\n<endpoint>\n<nonce b64u>\n<ts>", no
// trailing newline.
func buildPreimage() string {
	return strings.Join([]string{
		"v1",
		exampleNexusID,
		"ed25519",
		alicePubB64u,
		exampleEndpoint,
		exampleNonce,
		exampleTs,
	}, "\n")
}

func signPreimage(priv ed25519.PrivateKey, preimage string) string {
	sig := ed25519.Sign(priv, []byte(preimage))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// buildExampleOuter produces a canonical-JSON outer envelope.
// Field order is the lexicographic key order RFC 8785 requires: keys
// are sorted by code-point, no insignificant whitespace.
//
// Fields:
//   ciphertext        — base64-std of (nonce || aes-gcm-ciphertext)
//   ciphertext_sha256 — hex of SHA-256(ciphertext bytes)
//   msg_id            — UUIDv7
//   path_id           — nxc_<base64url(sha256(sort(pubA,pubB)))>
//   ts                — RFC3339Z
//   version           — "1"
//
// Locked-in test values (so the signature reproduces): the ciphertext
// is a fixed bytestring representing what AES-GCM might produce; the
// concrete plaintext-to-ciphertext path is shown in the inner-envelope
// example, not re-derived here. ciphertext_sha256 is recomputed from
// the bytes; msg_id is a fixed UUIDv7-shaped value.
func buildExampleOuter() string {
	// Lexicographic key order (RFC 8785). Indented with LF for
	// readability in the discovery doc; the wire bytes are the same
	// without the LFs (see exampleOuterWireHex).
	const ciphertextB64 = "AAECAwQFBgcICQoLDQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const msgID = "01979b0a-c0de-7eef-a000-000000000001"
	const ts = "2026-04-30T00:00:00Z"
	pathID := derivePathID(alicePubB64u, bobPubB64u)

	// Compute ciphertext_sha256 over the raw decoded ciphertext bytes
	// (NOT over the base64 representation).
	rawCipher, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		panic("discovery example: bad ciphertext b64")
	}
	digest := sha256.Sum256(rawCipher)
	digestHex := hex.EncodeToString(digest[:])

	// Build the canonical JSON manually so byte-equality is guaranteed.
	// Real senders should use a JCS library or the server-side
	// re-canonicalization carve-out documented in canonical_json.ergonomic_note.
	return `{` +
		`"ciphertext":"` + ciphertextB64 + `",` +
		`"ciphertext_sha256":"` + digestHex + `",` +
		`"msg_id":"` + msgID + `",` +
		`"path_id":"` + pathID + `",` +
		`"ts":"` + ts + `",` +
		`"version":"1"` +
		`}`
}

func signCanonical(priv ed25519.PrivateKey, canonical string) string {
	sig := ed25519.Sign(priv, []byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sig)
}

func computeCiphertextSHA256() string {
	const ciphertextB64 = "AAECAwQFBgcICQoLDQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	rawCipher, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		panic("discovery example: bad ciphertext b64")
	}
	digest := sha256.Sum256(rawCipher)
	return hex.EncodeToString(digest[:])
}

// derivePathID matches the pathId formula used by the pairflow handler
// and casket-go. Sort raw pubkeys lex, concat, SHA-256, base64url, prefix.
func derivePathID(aPubB64u, bPubB64u string) string {
	a, _ := base64.RawURLEncoding.DecodeString(aPubB64u)
	b, _ := base64.RawURLEncoding.DecodeString(bPubB64u)
	var first, second []byte
	if compare(a, b) < 0 {
		first, second = a, b
	} else {
		first, second = b, a
	}
	digest := sha256.Sum256(append(first, second...))
	return "nxc_" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func compare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}
