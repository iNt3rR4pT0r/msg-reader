import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import tailwindcss from '@tailwindcss/vite';
import { execSync } from 'child_process';
import { readFileSync } from 'fs';

// Detect if building for Tauri (TAURI_ENV_PLATFORM is set during tauri build/dev)
const isTauri = process.env.TAURI_ENV_PLATFORM !== undefined;

// Get version from git tag or package.json
function getVersion() {
  try {
    return execSync('git describe --tags --always 2>/dev/null').toString().trim();
  } catch {
    // Fallback to package.json version
    const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));
    return pkg.version || 'dev';
  }
}

const version = getVersion();

// Content Security Policy for the web build. The desktop app gets its policy
// from src-tauri/tauri.conf.json instead (Tauri has to add its own nonces).
// It is the second line of defense behind the HTML sanitizer: even if markup
// from an email slipped through, it could neither run scripts nor contact a
// remote server.
const WEB_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "object-src 'self' blob:",
  "frame-src 'self' blob:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

export default defineConfig({
  root: '.',
  // Use root path for Tauri, /msg-reader/ for GitHub Pages
  base: isTauri ? '/' : '/msg-reader/',
  publicDir: 'res',
  plugins: [
    tailwindcss(),
    nodePolyfills({
      include: ['buffer', 'stream', 'util', 'events', 'process'],
      globals: {
        Buffer: true,
        process: true,
      },
    }),
    {
      name: 'web-content-security-policy',
      apply: 'build',
      transformIndexHtml(html) {
        if (isTauri) return html;
        return html.replace(
          '<meta charset="UTF-8">',
          `<meta charset="UTF-8">\n    <meta http-equiv="Content-Security-Policy" content="${WEB_CSP}">`
        );
      },
    },
    {
      name: 'html-version-replace',
      transformIndexHtml(html) {
        return html.replace(/__VERSION__/g, version);
      },
    },
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: 'index.html',
    },
    // Tauri needs ES modules, web build uses default
    target: isTauri ? 'esnext' : 'es2020',
  },
  server: {
    port: 8080,
    // Don't auto-open browser for Tauri dev
    open: !isTauri,
    strictPort: true,
  },
  // Tauri needs to know about env variables
  envPrefix: ['VITE_', 'TAURI_'],
});
