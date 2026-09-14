import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

import { App } from './app';

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockRejectedValue(new TypeError('network down'));
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test('knowledge heading reuses page-title and keeps sources, cited page, kind, and pdf upload', async () => {
  render(<App initialPath='/knowledge' />);

  const heading = await screen.findByRole('heading', {
    level: 1,
    name: /^knowledge$/i,
  });
  expect(heading).toHaveClass('page-title');

  const sources = screen.getByRole('region', { name: /^sources$/i });
  expect(sources.closest('.case-file')).not.toBeNull();
  expect(
    screen.getByRole('region', { name: /^cited page$/i }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText(/kind/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/pdf/i)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /upload/i })).toBeInTheDocument();
});

test('calibration heading reuses page-title and keeps suite fields and expected rows', () => {
  render(<App initialPath='/calibration' />);

  const heading = screen.getByRole('heading', {
    level: 1,
    name: /^calibration$/i,
  });
  expect(heading).toHaveClass('page-title');

  const region = screen.getByRole('region', { name: /calibration/i });
  for (const label of ['Suite', 'n', 'ok', 'pass_k', 'cost_usd']) {
    expect(within(region).getByText(label, { selector: 'dt' })).toBeInTheDocument();
  }
  expect(
    screen.getByRole('columnheader', { name: /^expected$/i }),
  ).toBeInTheDocument();
  expect(region).toHaveTextContent('true_positive');
  expect(region).toHaveTextContent('false_positive');
});
