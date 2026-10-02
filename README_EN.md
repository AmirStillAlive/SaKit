# SaKit

Modern, private, client-side web toolkit for data encoding, decoding, inspecting, and config conversion.

Everything runs **100% locally in your browser** — zero data is uploaded to any server.

- **Live Application**: [https://amirstillalive.github.io/SaKit/](https://amirstillalive.github.io/SaKit/)
- [مستندات فارسی](README.md)

---

## 🛠 Available Tools

SaKit is engineered with a modular toolkit architecture making it seamless to register new browser tools. Current tools include:

### 1. Base64 Encoder / Decoder
- Encode and decode text or files to/from Base64.
- Real **UTF-8 safe** handling (Preserves Persian, Arabic, Unicode characters, and emojis without corruption).
- Standard Base64 and Base64URL support with automatic padding normalization.
- File upload support, one-click samples, copy, and file download.

### 2. NPV Tunnel Config Decryptor (.npvt & .npvs)
- Decrypt **`.npvt`** configs (AES-128 CTR using open-source white-box tables).
- Decrypt **`.npvs` Version 1 and Version 5** configs using ChaCha20-Poly1305 and gen2 white-box tables.
- Automatic link synthesis for **VLESS** (with Reality & TLS support), **VMess**, **Trojan**, **Shadowsocks** (including 2022 specs), and SOCKS5/HTTP proxies.
- Multi-file batch decryption, live protocol filtering, full-text search, and complete raw JSON export.

---

## 🚀 Key Architectural Features

- **100% Offline & Private (Zero Network Calls)**: All cryptography and conversions execute in local JavaScript.
- **PWA & Service Worker**: Assets and mathematical tables are precached for offline operation.
- **Modern Routing Architecture**: Clean SPA path routing compatible with GitHub Pages (via auto-generated `404.html`), Cloudflare Pages, and Vercel.
- **Unified Design System**: Powered by **React 19**, **Tailwind CSS v4**, and graphite dark tokens with a responsive collapsible sidebar.
- **Bilingual (English / Persian)**: Full RTL/LTR localization.

---

## 💻 Local Development

### Prerequisites
- Node.js 18+
- npm or pnpm

### Getting Started
```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build production bundle (outputs to docs/ for GitHub Pages)
npm run build

# Run unit tests & browser E2E test suite
npm test
npm run test:e2e
```

---

## 📜 Credits & License

Distributed under the **MIT License**.

- White-box reverse-engineering tables and NPV protocol parsing were ported based on the research and public code of [FrontierTM/Pantegnos](https://github.com/FrontierTM/Pantegnos) (MIT License).
- No proprietary binaries or assets were extracted from any closed-source application.
