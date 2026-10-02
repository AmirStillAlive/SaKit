import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import fs from 'node:fs';
import path from 'node:path';

// پلاگین برای کپی خودکار index.html به 404.html جهت کارکرد بی‌نقص SPA routing روی GitHub Pages
function generate404Plugin() {
  return {
    name: 'generate-404-html',
    closeBundle() {
      const outDir = path.resolve(__dirname, 'docs');
      const indexPath = path.join(outDir, 'index.html');
      const notFoundPath = path.join(outDir, '404.html');
      if (fs.existsSync(indexPath)) {
        fs.copyFileSync(indexPath, notFoundPath);
        console.log('✓ Generated docs/404.html for GitHub Pages SPA routing fallback');
      }
    },
  };
}

// خروجی build در docs/ می‌نشیند تا GitHub Pages از پوشهٔ /docs شاخهٔ main بالا بیاید.
export default defineConfig({
  plugins: [react(), tailwindcss(), generate404Plugin()],
  base: './',
  build: {
    outDir: 'docs',
    emptyOutDir: true,
  },
});
