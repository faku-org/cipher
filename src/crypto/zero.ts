import type { EncryptedPayload } from "./types";
import {
  hkdf,
  base64url,
  base64urlDecode,
  concat,
  encodeText,
  decodeText,
} from "./utils";
import { computeSharedSecret, generateEphemeralKeypair } from "./identity";

const AES_TAG_LENGTH = 128;
const AES_IV_LENGTH = 12;
const ENCRYPTION_INFO = "cipher-zero-v1";

/**
 * Encrypt a plaintext message for a recipient using Zero Mode.
 *
 * Flow:
 * 1. Generate ephemeral X25519 keypair
 * 2. ECDH(ephemeral.priv, recipient.pub) → shared secret
 * 3. HKDF(shared_secret, "cipher-zero-v1") → encryption key
 * 4. AES-256-GCM(key, plaintext) → ciphertext
 * 5. Output: ephemeral.pub || nonce || ciphertext
 */
export async function zeroEncrypt(
  plaintext: string,
  recipientPublicKeyRaw: Uint8Array
): Promise<EncryptedPayload> {
  const ephemeral = generateEphemeralKeypair();

  const sharedSecret = computeSharedSecret(
    ephemeral.privateKey,
    recipientPublicKeyRaw
  );

  const keyBytes = await hkdf(sharedSecret, ENCRYPTION_INFO, 32);

  const aesKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, [
    "encrypt",
  ]);

  const nonce = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        tagLength: AES_TAG_LENGTH,
      },
      aesKey,
      encodeText(plaintext)
    )
  );

  return { ephemeralPubKey: ephemeral.publicKey, ciphertext, nonce };
}

/**
 * Decrypt a Zero Mode message.
 *
 * Flow:
 * 1. Extract ephemeral public key from payload
 * 2. ECDH(recipient.priv, ephemeral.pub) → shared secret
 * 3. HKDF(shared_secret, "cipher-zero-v1") → encryption key
 * 4. AES-256-GCM decrypt
 */
export async function zeroDecrypt(
  payload: EncryptedPayload,
  recipientPrivateKey: Uint8Array
): Promise<string> {
  const sharedSecret = computeSharedSecret(
    recipientPrivateKey,
    payload.ephemeralPubKey
  );

  const keyBytes = await hkdf(sharedSecret, ENCRYPTION_INFO, 32);

  const aesKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, [
    "decrypt",
  ]);

  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: payload.nonce,
        tagLength: AES_TAG_LENGTH,
      },
      aesKey,
      payload.ciphertext
    )
  );

  return decodeText(plaintext);
}

/**
 * Encode a Zero Mode encrypted payload as a .cipher string.
 *
 * Format: base64url(ephemeral_pubkey || nonce || ciphertext)
 * Where:
 *   ephemeral_pubkey = 32 bytes (X25519 raw public key)
 *   nonce = 12 bytes (AES-GCM IV)
 *   ciphertext = variable (AES-256-GCM output with 16-byte tag)
 */
export function encodeCipherString(payload: EncryptedPayload): string {
  const combined = concat(payload.ephemeralPubKey, payload.nonce);
  const full = concat(combined, payload.ciphertext);
  return base64url(full);
}

/**
 * Decode a .cipher string back into an EncryptedPayload.
 */
export function decodeCipherString(data: string): EncryptedPayload {
  const bytes = base64urlDecode(data);
  if (bytes.length < 44) {
    throw new Error("Invalid cipher data: too short");
  }
  return {
    ephemeralPubKey: bytes.slice(0, 32),
    nonce: bytes.slice(32, 44),
    ciphertext: bytes.slice(44),
  };
}
