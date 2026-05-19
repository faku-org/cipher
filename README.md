# Cipher

> Encrypted messaging and file sharing. Zero data.

Cipher is a browser-based end-to-end encrypted messaging system with three operating modes: **P2P** (real-time via WebRTC), **Share** (view-once links), and **Zero** (fully offline).

Built as part of the Eternum / Itica SAS ecosystem.

## PoC Status

### ✅ Phase 1 — Crypto Core + Zero Mode (complete)

- [x] PBKDF2-SHA256 identity derivation (600k iterations, OWASP 2024)
- [x] HKDF-SHA256 subkey derivation
- [x] X25519 keypair generation (Web Crypto API)
- [x] AES-256-GCM encrypt/decrypt
- [x] Zero Mode: offline encrypt/decrypt with `.cipher` file export
- [x] Onboarding: passphrase → deterministic identity

### 🔜 Phase 2 — Share Mode
### 🔜 Phase 3 — File Encryption (Web Worker)
### 🔜 Phase 4 — P2P Mode (WebRTC + signaling server)
### 🔜 Phase 5 — Opt-in Peer Storage

## Tech Stack

- **Runtime:** Bun + Vite
- **Framework:** React 19 + TypeScript
- **Styles:** TailwindCSS v4
- **Crypto:** Web Crypto API (no external libraries)
- **Animations:** Motion (motion.dev)
- **Identity:** PBKDF2 | HKDF | X25519 (deterministic from passphrase)

## Brand

- **Colors:** Navy `#0F2854` → Sky `#BDE8F5`
- **Fonts:** DM Sans (UI), DM Mono (code), DM Serif Display (headings)
- **License:** Apache 2.0

## Development

```bash
bun install
bun dev        # dev server on :3004
bun run build  # production build
```

## Architecture

```
src/
├── crypto/
│   ├── types.ts       — Shared types
│   ├── utils.ts       — Encoding, PBKDF2, HKDF, SHA-256
│   ├── identity.ts    — Passphrase → identity derivation + X25519 keypairs
│   ├── zero.ts        — Zero Mode encrypt/decrypt + .cipher format
│   ├── words.ts       — Adjective-noun wordlist for usernames
│   └── index.ts       — Public API barrel
├── components/
│   ├── ModeSwitcher.tsx  — [• P2P ○ Share ○ Zero]
│   └── Onboarding.tsx    — Passphrase entry screen
├── modes/
│   └── ZeroMode.tsx      — Zero Mode UI (encrypt/decrypt)
├── App.tsx
├── main.tsx
└── index.css
```
