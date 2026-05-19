import type { CipherIdentity } from "./types";
import {
  deriveMasterSecret,
  hkdf,
} from "./utils";
import { x25519 } from "@noble/curves/ed25519.js";
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
  const privateKey = await hkdf(masterSecret, "keypair", 32);
  const publicKey = x25519.getPublicKey(privateKey);

  return {
    username,
    publicKey,
    privateKey,
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
 * Generate an ephemeral X25519 keypair (for Zero Mode / Share Mode)
 */
export function generateEphemeralKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const { secretKey, publicKey } = x25519.keygen();
  return { publicKey, privateKey: secretKey };
}

/**
 * Compute an ECDH shared secret between two X25519 keys
 */
export function computeSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}
