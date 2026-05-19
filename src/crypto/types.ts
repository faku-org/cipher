// Shared types for Cipher crypto operations

export interface CipherIdentity {
  username: string;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array;
}

export interface EncryptedPayload {
  /** Ephemeral public key (for Zero Mode) */
  ephemeralPubKey: Uint8Array;
  /** AES-GCM ciphertext */
  ciphertext: Uint8Array;
  /** AES-GCM nonce/IV (12 bytes) */
  nonce: Uint8Array;
}

export type CipherMode = "p2p" | "share" | "zero";
