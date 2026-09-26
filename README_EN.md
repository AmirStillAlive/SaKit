# SaKit

A minimal, offline Base64 encoder and decoder for text and files.

All processing runs entirely in the browser. No data is sent to any external server.

[مستندات فارسی](README.md)

## Features

- Base64 encoding and decoding with UTF-8 support (Persian, punctuation, and Unicode characters)
- Standard Base64 and Base64URL support
- Automatic padding restoration for unpadded inputs
- File upload support to encode file contents directly into Base64
- Copy to clipboard, download as text file, clear, and input/output swap
- Bilingual interface (Persian RTL and English LTR)
- Offline support with bundled fonts and inline icons

## Local Usage

No build step or dependencies required. Open `index.html` directly:

```powershell
start index.html
```

Or run using a simple local server:

```powershell
# Using Node.js
npx serve .

# Or using Python
python -m http.server 8000
```

Then visit `http://localhost:8000` in your browser.

## File Structure

```text
index.html       # UI structure and inline SVG icons
styles.css       # Visual styles and layout tokens
app.js           # Conversion logic, validation, and i18n
vendor/          # Self-hosted fonts for offline usage
.nojekyll        # GitHub Pages configuration
README.md        # Persian documentation (default)
README_EN.md     # English documentation
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
