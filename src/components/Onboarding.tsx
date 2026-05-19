import { useState, type FormEvent } from "react";

interface Props {
  onOnboard: (passphrase: string) => Promise<void>;
}

export default function Onboarding({ onOnboard }: Props) {
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (passphrase.length < 8) {
      setError("Passphrase must be at least 8 characters");
      return;
    }
    if (passphrase !== confirm) {
      setError("Passphrases don't match");
      return;
    }

    setLoading(true);
    try {
      await onOnboard(passphrase);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Derivation failed");
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="glass rounded-xl p-6 space-y-4">
        <div className="text-center">
          <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-blue-700/30 flex items-center justify-center">
            <svg className="w-6 h-6 text-sky-200" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <p className="text-amber-400/80 text-xs font-medium mb-1">⚠ No recovery</p>
          <p className="text-slate-400 text-xs">
            We don't store your passphrase. Lose it, lose your identity.
          </p>
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1">Passphrase</label>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="At least 8 characters"
            className="w-full bg-navy-900 border border-cipher-border rounded-lg px-3 py-2 text-sm font-mono text-white placeholder:text-slate-600 focus:outline-none focus:border-mid-400 transition-colors"
            autoFocus
          />
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1">Confirm</label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="Repeat passphrase"
            className="w-full bg-navy-900 border border-cipher-border rounded-lg px-3 py-2 text-sm font-mono text-white placeholder:text-slate-600 focus:outline-none focus:border-mid-400 transition-colors"
          />
        </div>

        {error && (
          <p className="text-red-400 text-xs text-center">{error}</p>
        )}

        <button
          type="submit"
          disabled={loading || !passphrase || !confirm}
          className="w-full bg-blue-700 hover:bg-blue-600 disabled:bg-navy-800 disabled:text-slate-600 text-white rounded-lg px-4 py-2.5 text-sm font-medium transition-colors"
        >
          {loading ? "Deriving identity..." : "Enter Cipher"}
        </button>
      </div>
    </form>
  );
}
