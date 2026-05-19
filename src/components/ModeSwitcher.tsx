import type { CipherMode } from "../crypto";

interface Props {
  current: CipherMode;
  onChange: (mode: CipherMode) => void;
}

const MODES: { key: CipherMode; label: string }[] = [
  { key: "p2p", label: "P2P" },
  { key: "share", label: "Share" },
  { key: "zero", label: "Zero" },
];

export default function ModeSwitcher({ current, onChange }: Props) {
  return (
    <div className="flex items-center gap-2">
      {MODES.map((m) => (
        <button
          key={m.key}
          onClick={() => onChange(m.key)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
            current === m.key
              ? "bg-blue-700/40 text-sky-200 border border-sky-300/20"
              : "text-slate-500 hover:text-slate-300 hover:bg-cipher-hover"
          }`}
        >
          <span
            className={`mode-dot ${current === m.key ? "active" : "inactive"}`}
          />
          {m.label}
        </button>
      ))}
    </div>
  );
}
