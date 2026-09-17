import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

import { App } from './app';

const cssPath = join(dirname(fileURLToPath(import.meta.url)), 'index.css');

function jsonResponse(status: number, body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

function cssBlock(css: string, selector: string): string {
  const match = css.match(
    new RegExp(
      `${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\{([^}]*)\\}`,
    ),
  );
  expect(match, `missing ${selector}`).toBeTruthy();
  return match?.[1] ?? '';
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

test('chrome-search stays a capped field in CSS source', () => {
  const chromeSearch = cssBlock(readFileSync(cssPath, 'utf8'), '.chrome-search');
  expect(chromeSearch).toContain('flex: 1');
  expect(chromeSearch).toContain('min-width: 10rem');
  expect(chromeSearch).toContain('text-align: left');
  expect(chromeSearch).toContain('max-width: 28rem');
});

test('chrome search stays a command-palette button', () => {
  render(<App />);

  const palette = screen.getByRole('button', { name: /command palette/i });
  expect(palette).toHaveClass('chrome-search');
  expect(palette.tagName).toBe('BUTTON');
  expect(
    screen.queryByRole('textbox', { name: /command palette/i }),
  ).toBeNull();
});

test('Calibration uses a page header, metric strip, and data table', () => {
  render(<App initialPath='/calibration' />);

  const heading = screen.getByRole('heading', {
    level: 1,
    name: /^calibration$/i,
  });
  expect(heading).toHaveClass('page-title');
  expect(heading.closest('.page-header')).not.toBeNull();

  const region = screen.getByRole('region', { name: /calibration/i });
  for (const label of ['Suite', 'n', 'ok', 'pass_k', 'cost_usd']) {
    const term = within(region).getByText(label, { selector: 'dt' });
    expect(term.closest('.metric-strip')).not.toBeNull();
  }
  expect(
    screen.getByRole('columnheader', { name: /^expected$/i }).closest('table'),
  ).toHaveClass('data-table');
  expect(region).toHaveTextContent('true_positive');
  expect(region).toHaveTextContent('false_positive');
});

test('Knowledge keeps panes and puts tools in a toolbar', async () => {
  fetchMock.mockRejectedValue(new TypeError('network down'));
  render(<App initialPath='/knowledge' />);

  const heading = await screen.findByRole('heading', {
    level: 1,
    name: /^knowledge$/i,
  });
  expect(heading).toHaveClass('page-title');
  expect(heading.closest('.page-header')).not.toBeNull();
  expect(
    screen.getByRole('region', { name: /^sources$/i }).closest('.case-file'),
  ).not.toBeNull();
  expect(document.querySelector('.page-toolbar')).not.toBeNull();
  expect(screen.getByLabelText(/kind/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/pdf/i)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /upload/i })).toBeInTheDocument();
});

test('Policies groups the five keys on a policy form', async () => {
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

  const heading = screen.getByRole('heading', {
    level: 1,
    name: /^policies$/i,
  });
  expect(heading).toHaveClass('page-title');
  expect(heading.closest('.page-header')).not.toBeNull();

  const scope = await screen.findByRole('textbox', { name: /scope/i });
  expect(scope.closest('.policy-form')).not.toBeNull();
  expect(screen.getByLabelText(/blast radius/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/auto.publish/i)).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: /budget/i })).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: /models/i })).toBeInTheDocument();
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
