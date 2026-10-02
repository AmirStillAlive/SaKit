# SaKit: Browser-Based Data & Config Toolkit

> Lightweight browser-based tools for encoding, decoding, inspecting, and converting data and configuration files.

SaKit is a client-side web toolkit built for developer productivity, format conversion, and security inspection. All computations, cryptographic algorithms, and file analyses execute directly inside your browser without backend dependencies.

- **Primary Deployment (GitHub Pages)**: [https://amirstillalive.github.io/SaKit/](https://amirstillalive.github.io/SaKit/)
- **Mirror Deployment (Cloudflare Pages / Vercel)**: Supported natively via root SPA routing.
- **[مستندات فارسی (Persian Documentation)](README_FA.md)**

---

## Privacy & Local Processing Architecture

1. **Zero User Data Transmission**: All primary tools run client-side to the maximum extent possible, and user input data is never sent to a backend for normal processing.
2. **Base64 Processing**: Handled entirely in-memory using browser-native `TextEncoder`, `TextDecoder`, and standard base64 utilities.
3. **NPV Config Decryption**: Pure client-side cryptographic computation in Web JavaScript (AES-128 CTR, ChaCha20-Poly1305, and White-Box table lookups).
4. **Static Asset Caching vs. Data Operations**:
   - The application registers a Service Worker (`sw.js`) and Web App Manifest (`manifest.webmanifest`).
   - Core application bundles, self-hosted Vazirmatn variable fonts, and compressed binary lookup tables (`gen2_tables.bin.z`) are pre-cached on initial visit.
   - Any claim of "fully offline" applies strictly to features that the current build can execute without network access.

---

## Available Tools

### 1. Base64 Encoder & Decoder (`/base64`)
- Full Unicode and UTF-8 round-trip support (handles Persian, Arabic, Chinese, and emojis without mangling).
- Standard Base64 and URL-safe Base64 (`Base64URL`) decoding with automatic missing padding (`=`) repair.
- File-to-Base64 conversion via native FileReader.
- Interactive controls: instant copy, `.txt` file export, quick sample loading, and bidirectional text swapping.

### 2. NPV Config Decryptor (`/npv`)
- Decrypts legacy `.npvt` configuration files with white-box mathematical tables.
- Decrypts `.npvs` Version 1 and Version 5 payloads using ChaCha20-Poly1305 and A16 KDK key derivation.
- Parses and generates ready-to-import client proxy links:
  - **VLESS** (with Reality, XTLS Vision, and standard TLS)
  - **VMess** (WebSocket, TCP, HTTP header obfuscation)
  - **Trojan** (TLS, WebSocket, SNI preservation)
  - **Shadowsocks** (Standard ciphers and Shadowsocks 2022)
  - **SOCKS5 and HTTP** proxies
- Multi-file batch decryption, live protocol filtering, and full raw JSON tree inspection.

---

## Tool Navigation & URLs

| Route | Tool |
| :--- | :--- |
| `/` or `/base64` | Base64 Encoder / Decoder |
| `/npv` | NPV Tunnel Config Decryptor |

- **GitHub Pages**: Deployed under the sub-path repository base `/SaKit/`. Fallback navigation is handled by an auto-generated `docs/404.html` SPA redirect.
- **Cloudflare Pages / Vercel**: Deployed at root domain `/` with native single-page fallback.
- **In-App Navigation**: The collapsible sidebar and mobile drawer allow instant, state-preserving switching between tools without full page reload.

---

## Supported Formats & Compatibility

| Tool | Format / Feature | Status | Notes |
| :--- | :--- | :--- | :--- |
| **Base64** | Standard Base64 | Supported | RFC 4648 §4 |
| **Base64** | Base64URL | Supported | RFC 4648 §5, padding repaired automatically |
| **Base64** | Binary File Encoding | Supported | Reads files as Base64 Data URL payloads |
| **NPV** | `.npvt` | Supported | AES-128 CTR with white-box lookup tables |
| **NPV** | `.npvs` Version 1 | Supported | JSON envelope; `appKey` and `passphrase` methods |
| **NPV** | `.npvs` Version 5 | Supported | Gen2 compact envelope; ChaCha20-Poly1305 and A16 KDK derivation |
| **NPV** | `.npvs` Versions 2 to 4, >5 | Unsupported | Unknown/undocumented payload structures; UI reports version explicitly |
| **NPV** | `.npvs` Recipient-bound | Unsupported | Bound to private hardware/ECDH keys; cannot be opened with public keys |

---

## Local Development

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

## Testing & Quality Assurance

```bash
# Run all unit tests and cryptography parity suites
npm test

# Run real browser end-to-end test (via Chrome DevTools Protocol)
npm run test:e2e
```

- **`test/links.test.mjs`**: 37 assertions testing proxy link builder correctness across VLESS, VMess, Trojan, and Shadowsocks.
- **`test/npvs-gen2.mjs`**: Verifies generation 2 A16 vectors, KDK key derivation, and Python/JS parity.
- **`test/npvs-parity.mjs`**: Verifies custodian KDF vectors, ChaCha20-Poly1305 cipher parity, and envelope unpackers.
- **`test/browser-e2e.mjs`**: Spawns a headless Chrome browser, exercises UI interactions, file drops, and DOM rendering.

---

## Deployment

### GitHub Pages (Default)
The repository build output targets the `docs/` folder on the `main` branch:
1. Run `npm run build` (generates `docs/index.html`, assets, and `docs/404.html`).
2. In GitHub Repository Settings -> Pages, select Source: **Deploy from a branch**, Branch: **main**, Folder: **/docs**.

### Cloudflare Pages and Vercel
- **Cloudflare Pages**: Set Build command `npm run build`, Output directory `docs`. Fully compatible with single-page application routing.
- **Vercel**: Set Output Directory `docs`.

---

## Architecture

```text
SaKit
├── App Shell
├── Tool Router
│   └── SPA routing with deployment-compatible fallback
├── Tools
│   ├── Base64Tool
│   │   └── UTF-8 / Unicode-safe encoding and decoding
│   └── NpvTool
│       └── Supported NPV configuration decoding and inspection
├── Shared UI Components
│   └── Tailwind CSS v4 + RTL-aware styling
└── Local-first runtime
    ├── Service Worker / PWA support
    └── Locally bundled fonts and static assets
```

All primary tools execute client-side to the maximum extent possible, and input data is not transmitted to a backend for normal processing.

---

## Security & Privacy Notes

- The NPV tool is provided for security research, configuration inspection, and user verification of config files.
- Avoid placing real passwords, private keys, UUIDs, or sensitive credentials in Issues, Pull Requests, public samples, or public repositories.
- File and input data processing occurs inside the browser, and the application requires no backend for normal decryption.
- Using a decoded configuration in another client or service may establish network connections to endpoints defined within that configuration. Verify server addresses and network parameters before connecting.
- Offline claims apply strictly to features that the current build can execute without network access. For any asset loaded lazily at runtime, this behavior must be documented explicitly.

---

## Independence & Disclaimer

- SaKit is an independent, open-source educational toolkit and is not affiliated with, endorsed by, or sponsored by NPV Tunnel, NapsternetV, or their respective developers.
- References to third-party file extensions and names are used strictly to describe format compatibility and interoperability.

---

## Attribution & Third-Party Notices

- **[FrontierTM/Pantegnos](https://github.com/FrontierTM/Pantegnos)**: Reference research and foundational implementation for NPV white-box lookup structures, KDF derivation, and envelope parsers.
- **[VibeFarsi](https://vibefarsi.ir/)**: Design reference for RTL UI principles, design system tokens, and Graphite dark theme.
- **[Vazirmatn](https://github.com/rastikerdar/vazirmatn)** by Saber Rastikerdar: Persian typography font under SIL Open Font License 1.1.
- **[Lucide](https://lucide.dev/)**: UI iconography under ISC License.
- Any additional third-party code, asset, or dependency in the final implementation must be documented before release in this section or in a dedicated notices file.

---

## Migration from npv-decrypt

- NPV features have been migrated from the standalone `npv-decrypt` project into SaKit as a first-class module (`/npv`). Ongoing maintenance will proceed under the unified SaKit repository.
- SaKit serves as the canonical project repository. The legacy repository is retained solely as migration history; once made private, documentation should not link to it as an active public source.

---

## License

SaKit is released under the [MIT License](LICENSE).
The SaKit license applies strictly to code and materials owned by SaKit; third-party code, fonts, assets, and dependencies remain under their respective independent licenses.
