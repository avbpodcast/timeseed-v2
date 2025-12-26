# TimeSeed v2 — Modular Edition

Standalone, fully offline cryptographic tool for:
- Deterministic LockIt passkey generation from a TimeSeed + date + optional pepper
- Text and file encryption/decryption using AES-256-GCM + Argon2id key derivation

**Runs entirely in your browser. No data leaves your device.**

## Quick Start
1. Download the files or clone the repo
2. Open `index.html` in any modern browser (Chrome/Firefox recommended)
3. Generate or enter a 50-character TimeSeed → select date → generate keys → use in LockIt

## Features
- Modular structure (easy to modify UI)
- Saved TimeSeeds ("book")
- Text and file encryption
- Dark/light theme
- No servers, no tracking, no recovery

## Files
- `index.html` — main page
- `styles.css` — appearance
- `script.js` — all interactive logic
- `argon2-bundle.js` — Argon2id library (crypto core)

## Security Note
All operations are client-side. Verify the source code. Use at your own risk.

CC0-1.0 Public Domain (except Flatpickr: MIT)
