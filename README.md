# SaKit

> Lightweight browser-based tools for encoding, decoding, inspecting, and converting data and configuration files.

SaKit is a client-side web toolkit built for developer productivity, format conversion, and security inspection. All computations, cryptographic algorithms, and file analyses execute directly inside your browser without backend dependencies.

- **Primary Deployment (GitHub Pages)**: [https://amirstillalive.github.io/SaKit/](https://amirstillalive.github.io/SaKit/)
- **Mirror Deployment (Cloudflare Pages / Vercel)**: Supported natively via root SPA routing.
- **[مستندات فارسی (Persian Documentation)](README_FA.md)**

---

## 🔒 Privacy & Local Processing Architecture

SaKit is engineered around a strict local-first privacy boundary:

1. **Zero User Data Transmission**: Neither input text, uploaded files, nor decrypted configurations are ever transmitted to any remote server or third-party API.
2. **Base64 Processing**: Handled entirely in-memory using browser-native `TextEncoder`, `TextDecoder`, and standard base64 utilities.
3. **NPV Config Decryption**: Pure client-side cryptographic computation in Web JavaScript (AES-128 CTR, ChaCha20-Poly1305, and White-Box table lookups).
4. **Static Asset Caching vs. Data Operations**:
   - The application registers a Service Worker (`sw.js`) and Web App Manifest (`manifest.webmanifest`).
   - All core scripts, stylesheets, self-hosted Vazirmatn variable fonts, and cipher tables (`gen2_tables.bin.z`) are pre-cached on initial visit in the browser's Cache Storage.
   - Subsequent visits run completely offline even when disconnected from the internet.

---

## 🛠 Available Tools

### 1. Base64 (`/base64`)
A full-featured Base64 encoder and decoder:
- Full Unicode and UTF-8 round-trip support (handles Persian, Arabic, Chinese, and emojis without mangling).
- Standard Base64 and URL-safe Base64 (`Base64URL`) decoding with automatic missing padding (`=`) repair.
- File-to-Base64 conversion via native FileReader.
- Interactive controls: instant copy, `.txt` file export, quick sample loading, and bidirectional text swapping.

### 2. NPV Config Decryptor (`/npv`)
Inspects and unpacks configuration archives produced by NPV Tunnel and NapsternetV:
- Decrypts legacy `.npvt` configuration files.
- Decrypts `.npvs` Version 1 and Version 5 payloads.
- Parses and generates ready-to-import client proxy links:
  - **VLESS** (with Reality, XTLS Vision, and standard TLS)
  - **VMess** (WebSocket, TCP, HTTP header obfuscation)
  - **Trojan** (TLS, WebSocket, SNI preservation)
  - **Shadowsocks** (Standard ciphers & Shadowsocks 2022)
  - **SOCKS5 & HTTP** proxies
- Multi-file batch decryption, live protocol filtering, and full raw JSON tree inspection.

---

## 🧭 Tool Navigation & URLs

SaKit supports clean client-side routing on modern web hosts:

| Route | Tool |
| :--- | :--- |
| `/` or `/base64` | Base64 Encoder / Decoder |
| `/npv` | NPV Tunnel Config Decryptor |

### Host Behavior
- **GitHub Pages**: Deployed under the sub-path repository base `/SaKit/`. Fallback navigation is handled by an auto-generated `docs/404.html` SPA redirect.
- **Cloudflare Pages / Vercel**: Deployed at root domain `/` with native single-page fallback.
- **In-App Navigation**: The collapsible sidebar and mobile drawer allow instant, state-preserving switching between tools without full page reload.

---

## 📋 Supported Formats & Compatibility

| Tool | Format / Feature | Status | Notes |
| :--- | :--- | :--- | :--- |
| **Base64** | Standard Base64 | Supported | RFC 4648 §4 |
| **Base64** | Base64URL | Supported | RFC 4648 §5, padding repaired automatically |
| **Base64** | Binary File Encoding | Supported | Reads files as Base64 Data URL payloads |
| **NPV** | `.npvt` | Supported | AES-128 CTR with white-box lookup tables |
| **NPV** | `.npvs` Version 1 | Supported | JSON envelope; `appKey` and `passphrase` methods |
| **NPV** | `.npvs` Version 5 | Supported | Gen2 compact envelope; ChaCha20-Poly1305 + A16 KDK derivation |
| **NPV** | `.npvs` Versions 2–4, >5 | Unsupported | Unknown/undocumented payload structures; UI reports version explicitly |
| **NPV** | `.npvs` Recipient-bound | Unsupported | Bound to private hardware/ECDH keys; cannot be opened with public keys |

---

## 💻 Usage

### Browser Usage
1. Open the [Online Demo](https://amirstillalive.github.io/SaKit/).
2. Select **Base64** or **NPV Config Decryptor** from the navigation sidebar.
3. Paste text or drag & drop configuration files into the input zone.
4. Copy the synthesized links or download the resulting text/JSON with one click.

---

## 🔧 Local Development

### Prerequisites
- Node.js 18.0.0 or higher
- npm 9.0.0 or higher

### Commands
```bash
# Clone repository
git clone https://github.com/AmirStillAlive/SaKit.git
cd SaKit

# Install dependencies
npm install

# Start local development server with Hot Module Replacement (HMR)
npm run dev

# Build production bundle for GitHub Pages (/docs directory)
npm run build

# Preview production build locally
npm run preview
```

---

## 🧪 Testing

SaKit maintains an automated test suite across unit, mathematical parity, and end-to-end browser environments:

```bash
# Run all unit tests & cryptography parity suites
npm test

# Run real browser end-to-end test (via Chrome DevTools Protocol)
npm run test:e2e
```

- **`test/links.test.mjs`**: 37 assertions testing proxy link builder correctness across VLESS, VMess, Trojan, and Shadowsocks.
- **`test/npvs-gen2.mjs`**: Verifies generation 2 A16 vectors, KDK key derivation, and Python/JS parity.
- **`test/npvs-parity.mjs`**: Verifies custodian KDF vectors, ChaCha20-Poly1305 cipher parity, and envelope unpackers.
- **`test/browser-e2e.mjs`**: Spawns a headless Chrome browser, exercises UI interactions, file drops, and DOM rendering.

---

## 🚀 Deployment

### GitHub Pages (Default)
The repository build output targets the `docs/` folder on the `main` branch:
1. Run `npm run build` (generates `docs/index.html`, assets, and `docs/404.html`).
2. In GitHub Repository Settings -> Pages, select Source: **Deploy from a branch**, Branch: **main**, Folder: **/docs**.

### Cloudflare Pages & Vercel
- **Cloudflare Pages**: Set Build command: `npm run build`, Output directory: `docs`. Fully compatible with single-page application routing.
- **Vercel**: Set Output Directory: `docs`.

---

## 🏗 Architecture

```text
SaKit App
 ├── App Shell (Responsive Collapsible Sidebar & Mobile Drawer)
 ├── Ambient Background FX (VibeFarsi Graphite & Cyberpunk Neon Grid)
 ├── Tool Router (SPA Path Routing with Fallback)
 ├── Tools
 │    ├── Base64Tool (UTF-8 Safe Engine)
 │    └── NpvTool (Multi-Format Cipher & Link Synthesis Engine)
 ├── Offline Core (PWA Service Worker + Self-Hosted Vazirmatn Fonts)
 └── Shared UI Components (VibeFarsi Design Tokens & Tailwind CSS v4)
```

---

## 🛡 Security & Privacy Notes

- NPV decryption is provided for security research, configuration backup, and interoperability auditing.
- Do not commit real credentials, VPN connection passwords, or private configurations to public repositories or issue trackers.
- All decryption runs in your browser. However, configurations extracted from third-party files route traffic to the servers configured by their creators; verify server hostnames before using them.

---

## ⚖️ Independence & Disclaimer

SaKit is an independent, open-source educational toolkit. It is **not** affiliated with, endorsed by, or sponsored by NPV Tunnel, NapsternetV, or their respective developers. All references to third-party file extensions and software names are used strictly for format compatibility and interoperability descriptions.

---

## 📜 Attribution & Third-Party Notice

- **[FrontierTM/Pantegnos](https://github.com/FrontierTM/Pantegnos)**: Reference research and open-source implementation for NPV white-box lookup structures, KDF derivation, and envelope parsers.
- **[VibeFarsi](https://vibefarsi.ir)**: Design rules, Graphite dark theme tokens, and typography guidelines.
- **[Vazirmatn Font](https://github.com/rastikerdar/vazirmatn)** by Saber Rastikerdar: Open Font License (OFL).
- **[Lucide Icons](https://lucide.dev)**: ISC License.

---

## 🔄 Migration from npv-decrypt

The capabilities of the standalone `npv-decrypt` tool have been merged into SaKit as a first-class module (`/npv`). Maintenance and future updates will proceed under the unified SaKit repository.

---

## 🗺 Roadmap

- [ ] Additional hash tools (MD5, SHA-256, Keccak).
- [ ] JSON / YAML / TOML cross-converter with syntax highlighting.
- [ ] V2Ray / Sing-box config syntax validator.

---

## 📄 License

SaKit is distributed under the [MIT License](LICENSE).
