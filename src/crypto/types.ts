// Shared types for Cipher crypto operations

export interface CipherIdentity {
  username: string;
  /** Raw public key (32 bytes, X25519) */
  publicKey: Uint8Array;
  /** Raw private key (32 bytes, X25519 clamped) */
  privateKey: Uint8Array;
}

export interface EncryptedPayload {
  /** Ephemeral public key (32 bytes, for Zero Mode) */
  ephemeralPubKey: Uint8Array;
  /** AES-GCM ciphertext */
  ciphertext: Uint8Array;
  /** AES-GCM nonce/IV (12 bytes) */
  nonce: Uint8Array;
}

export type CipherMode = "p2p" | "share" | "zero";
