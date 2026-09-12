// @vitest-environment node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createServer } from 'vite';
import { expect, test } from 'vitest';

const webRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const cssPath = join(webRoot, 'src/index.css');

const TOKENS = [
  "--font-sans: 'IBM Plex Sans', ui-sans-serif, sans-serif;",
  "--font-mono: 'IBM Plex Mono', ui-monospace, monospace;",
  "--font-serif: 'Source Serif 4', ui-serif, serif;",
  '--color-page: #0e1114;',
  '--color-surface: #161b20;',
  '--color-hairline: #2a333c;',
  '--color-ink: #e8e4dc;',
  '--color-signal: #d4a017;',
  '--color-sev-critical: #c45c26;',
  '--color-sev-high: #c9a227;',
  '--color-sev-medium: #8a7a4b;',
  '--color-sev-low: #6b7c85;',
];

test('theme tokens reject Inter and purple', () => {
  const css = readFileSync(cssPath, 'utf8');

  expect(css).toContain("@import 'tailwindcss'");
  expect(css).toContain('@theme');
  for (const token of TOKENS) {
    expect(css).toContain(token);
  }

  expect(css).not.toMatch(/Inter|Roboto|Space Grotesk/i);
  expect(css).not.toMatch(/purple|violet|#7c3aed|#8b5cf6|#a855f7|#6d28d9/i);
});

test('vite emits theme tokens as root custom properties', async () => {
  const server = await createServer({
    root: webRoot,
    configFile: join(webRoot, 'vite.config.ts'),
    appType: 'custom',
    logLevel: 'silent',
    server: { middlewareMode: true },
    optimizeDeps: { noDiscovery: true },
  });
  try {
    const result = await server.transformRequest('/src/index.css');
    const css = result?.code ?? '';
    expect(css).toMatch(
      /:root(?:,\s*:host)?[^{]*\{[^}]*--color-page:\s*#0e1114/,
    );
    expect(css).toMatch(
      /:root(?:,\s*:host)?[^{]*\{[^}]*--color-ink:\s*#e8e4dc/,
    );
  } finally {
    await server.close();
  }
}, 20_000);
