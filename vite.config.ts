import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// The build output is placed in docs/ for GitHub Pages publishing.
// Static assets in public/ (such as 404.html for SPA redirect and _redirects for Cloudflare)
// are automatically copied into docs/ on build.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: './',
  build: {
    outDir: 'docs',
    emptyOutDir: true,
  },
});
