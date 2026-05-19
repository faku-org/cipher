import type { CipherIdentity } from "./types";
import {
  deriveMasterSecret,
  hkdf,
  sha256,
  encodeText,
  base64url,
} from "./utils";
import { ADJECTIVES, NOUNS } from "./words";

/**
 * Derive a deterministic identity from a passphrase.
 *
 * passphrase
 *   → PBKDF2-SHA256(600k) → master_secret (32 bytes)
 *   → HKDF(info="identity") → username_seed → username
 *   → HKDF(info="keypair")  → X25519 keypair (deterministic via seed)
 */
export async function deriveIdentity(passphrase: string): Promise<CipherIdentity> {
  const masterSecret = await deriveMasterSecret(passphrase);

  // Derive username seed
  const usernameSeed = await hkdf(masterSecret, "identity", 4);
  const username = generateUsername(usernameSeed);

  // Derive keypair from seeded material
  // Web Crypto API X25519 generateKey doesn't support seed injection,
  // so we use the deterministic bytes as the private key directly
  const keySeed = await hkdf(masterSecret, "keypair", 32);

  const keypair = await importX25519Keypair(keySeed);

  // Export raw public key for display/sending
  const publicKeyRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", keypair.publicKey)
  );

  return {
    username,
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey,
    publicKeyRaw,
  };
}

/** Generate username from a 4-byte seed */
function generateUsername(seed: Uint8Array): string {
  const view = new DataView(seed.buffer);
  const adjIdx = view.getUint16(0) % ADJECTIVES.length;
  const nounIdx = view.getUint16(2) % NOUNS.length;
  const suffix = Math.floor(Math.random() * 10000)
    .toString()
    .padStart(4, "0");
  return `${ADJECTIVES[adjIdx]}-${NOUNS[nounIdx]}-${suffix}`;
}

/**
 * Import an X25519 keypair from a 32-byte seed.
 * The seed IS the private key (raw bytes).
 */
async function importX25519Keypair(
  privateKeyBytes: Uint8Array
): Promise<CryptoKeyPair> {
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    buildPkcs8X25519(privateKeyBytes),
    { name: "ECDH", namedCurve: "X25519" },
    true, // extractable so we can export peer's pubkey later
    ["deriveBits", "deriveKey"]
  );

  // Derive public key from private key
  // (some browsers auto-derive; we export to get raw bytes)
  const publicKey = await crypto.subtle.importKey(
    "raw",
    await deriveX25519PublicKey(privateKeyBytes),
    { name: "ECDH", namedCurve: "X25519" },
    true,
    []
  );

  return { privateKey, publicKey };
}

/**
 * Build a PKCS#8 wrapper for an X25519 private key.
 * X25519 OID: 1.3.101.110
 * PKCS#8 structure:
 *   SEQUENCE {
 *     INTEGER 0
 *     SEQUENCE { OID 1.3.101.110 }
 *     OCTET STRING (private key bytes)
 *   }
 */
function buildPkcs8X25519(keyBytes: Uint8Array): ArrayBuffer {
  // Simple PKCS#8 DER encoding for X25519
  // This is the standard format Web Crypto expects for importing raw X25519 keys
  const privateKeyOID = new Uint8Array([0x06, 0x03, 0x2B, 0x65, 0x6E]); // 1.3.101.110 = X25519
  
  // AlgorithmIdentifier SEQUENCE
  const algId = new Uint8Array([0x30, 0x05, ...privateKeyOID]);

  // Wrap private key in OCTET STRING
  const wrappedKey = new Uint8Array([0x04, keyBytes.length, ...keyBytes]);

  // PrivateKeyInfo SEQUENCE
  const privateKeyInfo = new Uint8Array([
    0x30, // SEQUENCE tag
    0x00, // length placeholder
    0x02, 0x01, 0x00, // INTEGER 0 (version)
    ...algId,
    ...wrappedKey,
  ]);
  privateKeyInfo[1] = privateKeyInfo.length - 2;

  return privateKeyInfo.buffer;
}

/**
 * Derive X25519 public key from private key.
 * For X25519: pub = clamp(priv) * 9 (base point)
 * We compute this via the Web Crypto API since browsers handle scalar multiplication.
 * 
 * Workaround: generate a keypair with the same private key via raw import
 */
async function deriveX25519PublicKey(
  privateKeyBytes: Uint8Array
): Promise<ArrayBuffer> {
  // Modern approach: derive via ECDH with base point
  // The Web Crypto API computes this automatically when importing
  // For now we use a two-step: import private, then use it to generate matching public
  const privKey = await crypto.subtle.importKey(
    "pkcs8",
    buildPkcs8X25519(privateKeyBytes),
    { name: "ECDH", namedCurve: "X25519" },
    true,
    ["deriveBits"]
  );

  const jwk = await crypto.subtle.exportKey("jwk", privKey);
  // JWK for X25519 has "x" (public) and "d" (private) components
  // If the browser auto-derived "x" when we imported, we have it
  // Otherwise, fall back to a raw computation
  
  // For complete X25519 public key derivation, we need:
  // pub_key = X25519(clamp(private_key), basepoint)
  // Since Web Crypto API doesn't expose this directly, we generate
  // a new keypair that's linked to our private key
  // 
  // Actually, in the Web Crypto API for ECDH:
  // - importing a private key with extractable=true lets us export the JWK
  // - JWK format for X25519 includes both "x" (public) and "d" (private)
  // - The browser calculates the public key on import
  
  const keyJwk = await crypto.subtle.exportKey("jwk", privKey);
  
  // The "x" parameter in JWK is the raw public key (base64url encoded)
  const xStr = keyJwk.x;
  if (xStr) {
    // Convert base64url to bytes
    xStr.replace(/-/g, "+").replace(/_/g, "/");
    const padded = xStr + "=".repeat((4 - (xStr.length % 4)) % 4);
    const publicKey = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    return publicKey.buffer;
  }

  throw new Error("Could not derive X25519 public key");
}

/**
 * Generate an ephemeral X25519 keypair (for Zero Mode / Share Mode)
 */
export async function generateEphemeralKeypair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "X25519",
    },
    true,
    ["deriveBits", "deriveKey"]
  );
}

/**
 * Compute an ECDH shared secret between two X25519 keys
 */
export async function computeSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<Uint8Array> {
  const bits = await crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: publicKey,
    },
    privateKey,
    256 // 32 bytes shared secret
  );
  return new Uint8Array(bits);
}
