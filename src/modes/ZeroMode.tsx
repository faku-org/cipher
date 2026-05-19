import { useState, type FormEvent } from "react";
import type { CipherIdentity } from "../crypto";
import {
  zeroEncrypt,
  zeroDecrypt,
  encodeCipherString,
  decodeCipherString,
  base64url,
} from "../crypto";

interface Props {
  identity: CipherIdentity;
}

type ZeroTab = "encrypt" | "decrypt";

export default function ZeroMode({ identity }: Props) {
  const [tab, setTab] = useState<ZeroTab>("encrypt");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyFeedback, setCopyFeedback] = useState<string | null>(null);

  // Encrypt state
  const [recipientPubkey, setRecipientPubkey] = useState("");
  const [message, setMessage] = useState("");
  const [cipherOutput, setCipherOutput] = useState<string | null>(null);

  // Decrypt state
  const [cipherInput, setCipherInput] = useState("");
  const [decryptedOutput, setDecryptedOutput] = useState<string | null>(null);

  const publicKeyBase64 = identity.publicKey
    ? base64url(identity.publicKey)
    : "";

  const handleEncrypt = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setCipherOutput(null);

    if (!recipientPubkey.trim()) {
      setError("Paste the recipient's public key");
      return;
    }
    if (!message.trim()) {
      setError("Enter a message");
      return;
    }

    setLoading(true);
    try {
      // Decode recipient's pubkey from base64url
      let pubkeyBytes: Uint8Array;
      try {
        pubkeyBytes = Uint8Array.from(atob(recipientPubkey.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
        // Re-encode as base64url for consistency
        const clean = base64url(pubkeyBytes);
        pubkeyBytes = Uint8Array.from(atob(clean.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
      } catch {
        // Try base64url decode
        pubkeyBytes = Uint8Array.from(atob(recipientPubkey.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(recipientPubkey.length / 4) * 4, "=")), c => c.charCodeAt(0));
      }

      if (pubkeyBytes.length !== 32) {
        setError("Invalid public key (must be 32 bytes)");
        setLoading(false);
        return;
      }

      const payload = await zeroEncrypt(message, pubkeyBytes);
      const cipherStr = encodeCipherString(payload);
      setCipherOutput(cipherStr);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Encryption failed");
    }
    setLoading(false);
  };

  const handleDecrypt = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setDecryptedOutput(null);

    if (!cipherInput.trim()) {
      setError("Paste the cipher text");
      return;
    }

    setLoading(true);
    try {
      const payload = decodeCipherString(cipherInput.trim());
      const plaintext = await zeroDecrypt(payload, identity.privateKey);
      setDecryptedOutput(plaintext);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Decryption failed — wrong key or corrupted data"
      );
    }
    setLoading(false);
  };

  const handleCopy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopyFeedback(label);
      setTimeout(() => setCopyFeedback(null), 2000);
    } catch {
      // Fallback: select all text in a textarea
    }
  };

  const handleDownload = () => {
    if (!cipherOutput) return;
    const blob = new Blob([cipherOutput], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cipher-${Date.now()}.cipher`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Identity Card */}
      <div className="glass rounded-xl p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-slate-500 uppercase tracking-wider">
            Identity
          </span>
          <button
            onClick={() => handleCopy(publicKeyBase64, "Public key copied")}
            className="text-xs text-sky-300 hover:text-sky-200 transition-colors"
          >
            {copyFeedback === "Public key copied" ? "✓ Copied" : "Copy pubkey"}
          </button>
        </div>
        <p className="font-serif text-xl text-sky-100 mb-1">
          {identity.username}
        </p>
        <p className="font-mono text-xs text-slate-500 break-all">
          {publicKeyBase64}
        </p>
      </div>

      {/* Tab switcher */}
      <div className="flex gap-1 glass rounded-xl p-1 w-fit">
        <button
          onClick={() => setTab("encrypt")}
          className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all ${
            tab === "encrypt"
              ? "bg-blue-700/50 text-sky-200"
              : "text-slate-500 hover:text-slate-300"
          }`}
        >
          Encrypt
        </button>
        <button
          onClick={() => setTab("decrypt")}
          className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all ${
            tab === "decrypt"
              ? "bg-blue-700/50 text-sky-200"
              : "text-slate-500 hover:text-slate-300"
          }`}
        >
          Decrypt
        </button>
      </div>

      {/* Encrypt Tab */}
      {tab === "encrypt" && (
        <form onSubmit={handleEncrypt} className="glass rounded-xl p-4 space-y-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Recipient's Public Key
            </label>
            <input
              type="text"
              value={recipientPubkey}
              onChange={(e) => setRecipientPubkey(e.target.value)}
              placeholder="Paste base64 public key..."
              className="w-full bg-navy-900 border border-cipher-border rounded-lg px-3 py-2 text-xs font-mono text-white placeholder:text-slate-600 focus:outline-none focus:border-mid-400 transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Message
            </label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Type your message..."
              rows={4}
              className="w-full bg-navy-900 border border-cipher-border rounded-lg px-3 py-2 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-mid-400 transition-colors resize-none"
            />
          </div>

          {error && (
            <p className="text-red-400 text-xs">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading || !recipientPubkey || !message}
            className="w-full bg-blue-700 hover:bg-blue-600 disabled:bg-navy-800 disabled:text-slate-600 text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors"
          >
            {loading ? "Encrypting..." : "Encrypt →"}
          </button>

          {cipherOutput && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-green-400">✓ Encrypted</span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => handleCopy(cipherOutput, "Cipher text copied")}
                    className="text-xs text-sky-300 hover:text-sky-200 transition-colors"
                  >
                    {copyFeedback === "Cipher text copied" ? "✓ Copied" : "Copy"}
                  </button>
                  <button
                    type="button"
                    onClick={handleDownload}
                    className="text-xs text-sky-300 hover:text-sky-200 transition-colors"
                  >
                    Download
                  </button>
                </div>
              </div>
              <textarea
                readOnly
                value={cipherOutput}
                rows={3}
                className="w-full bg-navy-900/50 border border-green-800/30 rounded-lg px-3 py-2 text-xs font-mono text-green-300 resize-none"
              />
              <p className="text-xs text-slate-500">
                Send this cipher text to the recipient. They need their private key to decrypt it.
              </p>
            </div>
          )}
        </form>
      )}

      {/* Decrypt Tab */}
      {tab === "decrypt" && (
        <form onSubmit={handleDecrypt} className="glass rounded-xl p-4 space-y-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Cipher Text
            </label>
            <textarea
              value={cipherInput}
              onChange={(e) => setCipherInput(e.target.value)}
              placeholder="Paste cipher text..."
              rows={4}
              className="w-full bg-navy-900 border border-cipher-border rounded-lg px-3 py-2 text-xs font-mono text-white placeholder:text-slate-600 focus:outline-none focus:border-mid-400 transition-colors resize-none"
            />
          </div>

          {error && (
            <p className="text-red-400 text-xs">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading || !cipherInput}
            className="w-full bg-blue-700 hover:bg-blue-600 disabled:bg-navy-800 disabled:text-slate-600 text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors"
          >
            {loading ? "Decrypting..." : "Decrypt →"}
          </button>

          {decryptedOutput && (
            <div className="space-y-1">
              <span className="text-xs text-green-400">✓ Decrypted</span>
              <div className="bg-navy-900/50 border border-green-800/30 rounded-lg px-3 py-3">
                <p className="text-sm text-sky-100 whitespace-pre-wrap">
                  {decryptedOutput}
                </p>
              </div>
            </div>
          )}
        </form>
      )}

      {/* Info footer */}
      <div className="text-center text-xs text-slate-600">
        All encryption happens in your browser. No data is sent to any server.
      </div>
    </div>
  );
}
