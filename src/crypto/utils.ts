// Encoding utilities for Cipher

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Encode a string to Uint8Array */
export function encodeText(s: string): Uint8Array {
  return encoder.encode(s);
}

/** Decode a Uint8Array to string */
export function decodeText(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Base64url encode (no padding, no +/ or trailing =) */
export function base64url(data: Uint8Array): string {
  const base64 = btoa(String.fromCodePoint(...data));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Base64url decode */
export function base64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

/** Concatenate two Uint8Arrays */
export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a);
  result.set(b, a.length);
  return result;
}

/** Format bytes as hex string */
export function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const PBKDF2_SALT = encodeText("cipher-v1");
const PBKDF2_ITERATIONS = 600_000;
const KEY_LENGTH = 256; // bits

/** Derive a master secret (256-bit) from a passphrase using PBKDF2-SHA256 */
export async function deriveMasterSecret(passphrase: string): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encodeText(passphrase.normalize("NFKC")),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: PBKDF2_SALT,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    KEY_LENGTH
  );

  return new Uint8Array(bits);
}

/** Derive subkeys using HKDF-SHA256 */
export async function hkdf(
  ikm: Uint8Array,
  info: string,
  length: number = 32
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    ikm,
    "HKDF",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      salt: new Uint8Array(32), // zero salt for deterministic derivation
      hash: "SHA-256",
      info: encodeText(info),
    },
    key,
    length * 8
  );

  return new Uint8Array(bits);
}

/** Hash data with SHA-256 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}
