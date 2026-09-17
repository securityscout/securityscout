import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

import { App } from './app';

const cssPath = join(dirname(fileURLToPath(import.meta.url)), 'index.css');

const THEME_TOKENS = [
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

function jsonResponse(status: number, body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

function cssBlock(css: string, selector: string): string {
  const start = css.indexOf(selector);
  expect(start, `missing ${selector}`).toBeGreaterThan(-1);
  const open = css.indexOf('{', start);
  const close = css.indexOf('}', open);
  return css.slice(open + 1, close);
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test('index.css source sets page-title and console h2 sizes', () => {
  const css = readFileSync(cssPath, 'utf8');

  const pageTitle = cssBlock(css, '.page-title');
  expect(pageTitle).toContain('font-family: var(--font-serif)');
  expect(pageTitle).toContain('font-size: 22px');
  expect(pageTitle).toContain('font-weight: 600');
  expect(pageTitle).toContain('line-height: 1.2');

  const consoleH2 = cssBlock(css, '.console h2');
  expect(consoleH2).toContain('font-size: 15px');
  expect(consoleH2).toContain('font-weight: 600');

  const chromeSearch = cssBlock(css, '.chrome-search');
  expect(chromeSearch).toContain('flex: 1');
  expect(chromeSearch).toContain('min-width: 10rem');
  expect(chromeSearch).toContain('text-align: left');

  for (const token of THEME_TOKENS) {
    expect(css).toContain(token);
  }

  const focusAt = css.indexOf(':focus-visible');
  expect(focusAt).toBeGreaterThan(-1);
  const selectorStart = css.lastIndexOf('}', focusAt);
  const selector = css.slice(selectorStart + 1, css.indexOf('{', focusAt));
  expect(selector).toMatch(/button/);
  expect(selector).toMatch(/input/);
  expect(selector).toMatch(/select/);
  expect(selector).toMatch(/textarea/);
  expect(cssBlock(css, ':focus-visible')).toContain(
    'outline: 1px solid var(--color-signal)',
  );
});

test('chrome search stays a command-palette button', () => {
  render(<App />);

  const palette = screen.getByRole('button', { name: /command palette/i });
  expect(palette).toHaveClass('chrome-search');
  expect(palette.tagName).toBe('BUTTON');
  expect(
    screen.queryByRole('textbox', { name: /command palette/i }),
  ).toBeNull();

  const meter = screen.getByRole('meter', { name: /budget remaining/i });
  expect(meter).toHaveAttribute('aria-valuemax', '200');
});

test('Policies heading reuses page-title', () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      scope: {},
      blast_radius: 'safe',
      budget: {},
      models: {},
      auto_publish: false,
    }),
  );

  render(<App initialPath='/policies' />);

  expect(
    screen.getByRole('heading', { level: 1, name: /^policies$/i }),
  ).toHaveClass('page-title');
});

test('Graph heading reuses page-title and stays the only heading', () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { engagement_id: 'eng_1', nodes: [], hops: [] }),
  );

  render(<App initialPath='/graph/eng_1' />);

  const heading = screen.getByRole('heading');
  expect(heading).toHaveTextContent('Graph');
  expect(heading).toHaveClass('page-title');
  expect(screen.getAllByRole('heading')).toHaveLength(1);
});

test('Run heading reuses page-title', () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      id: 'run_1',
      engagement_id: 'eng_1',
      status: 'queued',
    }),
  );

  render(<App initialPath='/engagements/eng_1/runs/run_1' />);

  expect(screen.getByRole('heading', { name: /Run run_1/ })).toHaveClass(
    'page-title',
  );
});

test('/ still GETs /engagements first', async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, { engagements: [] }));

  render(<App initialPath='/' />);

  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled());
  expect(fetchMock.mock.calls[0][0]).toBe('/engagements');
  expect(fetchMock.mock.calls[0][1]).toEqual(
    expect.objectContaining({ method: 'GET' }),
  );
});
