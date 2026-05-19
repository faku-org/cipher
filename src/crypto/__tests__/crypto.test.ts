import { describe, test, expect } from "bun:test";

// We test crypto operations using the Web Crypto API available in Bun
// Note: X25519 may not be fully available in Bun's Web Crypto implementation;
// the full crypto flow is primarily designed for browser runtime

// eslint-disable-next-line
const testUtils = async () => {
  const mod = await import("../utils");
  return mod;
};

describe("Crypto Utilities", () => {
  test("base64url roundtrip", async () => {
    const { base64url, base64urlDecode, encodeText, decodeText } = await import("../utils");
    const original = "Hello, Cipher! 🔐";
    const encoded = base64url(encodeText(original));
    const decoded = decodeText(base64urlDecode(encoded));
    expect(decoded).toBe(original);
  });

  test("PBKDF2 derivation produces 32 bytes", async () => {
    const { deriveMasterSecret } = await import("../utils");
    const secret = await deriveMasterSecret("test-passphrase-123");
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
  });

  test("PBKDF2 is deterministic", async () => {
    const { deriveMasterSecret } = await import("../utils");
    const a = await deriveMasterSecret("same-passphrase");
    const b = await deriveMasterSecret("same-passphrase");
    expect(a).toEqual(b);
  });

  test("PBKDF2 produces different output for different passphrases", async () => {
    const { deriveMasterSecret } = await import("../utils");
    const a = await deriveMasterSecret("passphrase-one");
    const b = await deriveMasterSecret("passphrase-two");
    expect(a).not.toEqual(b);
  });

  test("HKDF derivation", async () => {
    const { deriveMasterSecret, hkdf } = await import("../utils");
    const master = await deriveMasterSecret("hkdf-test");
    const derived = await hkdf(master, "test-context", 32);
    expect(derived).toBeInstanceOf(Uint8Array);
    expect(derived.length).toBe(32);
  });

  test("HKDF is deterministic", async () => {
    const { deriveMasterSecret, hkdf } = await import("../utils");
    const master = await deriveMasterSecret("hkdf-deterministic");
    const a = await hkdf(master, "same-context", 16);
    const b = await hkdf(master, "same-context", 16);
    expect(a).toEqual(b);
  });

  test("SHA-256 produces correct length", async () => {
    const { sha256, encodeText } = await import("../utils");
    const hash = await sha256(encodeText("hello"));
    expect(hash.length).toBe(32);
  });
});
