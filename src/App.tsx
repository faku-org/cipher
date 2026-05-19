import type { CipherIdentity, CipherMode } from "./crypto";
import { deriveIdentity } from "./crypto";
import ModeSwitcher from "./components/ModeSwitcher";
import Onboarding from "./components/Onboarding";
import ZeroMode from "./modes/ZeroMode";
import { useState, useCallback } from "react";

export default function App() {
  const [identity, setIdentity] = useState<CipherIdentity | null>(null);
  const [mode, setMode] = useState<CipherMode>("zero");

  const handleOnboard = useCallback(async (passphrase: string) => {
    const id = await deriveIdentity(passphrase);
    setIdentity(id);
  }, []);

  const handleLogout = useCallback(() => {
    setIdentity(null);
  }, []);

  if (!identity) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <h1 className="font-serif text-5xl text-sky-200 mb-2">Cipher</h1>
            <p className="text-slate-400 text-sm">
              Encrypted messaging. Zero data.
            </p>
          </div>
          <Onboarding onOnboard={handleOnboard} />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="glass border-b border-cipher-border px-4 py-3">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h1 className="font-serif text-2xl text-sky-200">Cipher</h1>
            <ModeSwitcher current={mode} onChange={setMode} />
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm font-mono text-sky-300">
              {identity.username}
            </span>
            <button
              onClick={handleLogout}
              className="text-xs text-slate-500 hover:text-red-400 transition-colors px-2 py-1 rounded"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-4xl mx-auto w-full p-4">
        {mode === "zero" && <ZeroMode identity={identity} />}
        {mode === "share" && (
          <div className="flex items-center justify-center h-64 text-slate-500">
            Share Mode — próximamente
          </div>
        )}
        {mode === "p2p" && (
          <div className="flex items-center justify-center h-64 text-slate-500">
            P2P Mode — próximamente
          </div>
        )}
      </main>
    </div>
  );
}
