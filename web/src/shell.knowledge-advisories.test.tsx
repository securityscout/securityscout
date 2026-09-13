import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

import { App } from './app';

function jsonResponse(status: number, body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

const livePdf = {
  id: 'ks_live',
  kind: 'pdf',
  title: 'q3-2025-assessment.pdf',
  uri: 'q3-2025-assessment.pdf',
  assessment_date: '2025-06-01',
  sha256: 'a'.repeat(64),
  citation: 'q3-2025-assessment.pdf p.4',
  page: 4,
  page_text: 'orders IDOR on /v1 reachable without a session',
};

const liveAdvisory = {
  id: 'ks_ghsa',
  kind: 'github_advisory',
  title: 'SQL injection in oldpkg',
  uri: 'GHSA-aaaa-bbbb-cccc',
  assessment_date: '2025-06-01',
  sha256: 'd'.repeat(64),
  citation: 'SQL injection in oldpkg GHSA-aaaa-bbbb-cccc',
  page: null,
  page_text: 'SQLi in package oldpkg',
};

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test('Index advisories POSTs /knowledge/github-advisories and lists the returned source', async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(201, { org: 'acme', repo: null, sources: [liveAdvisory] }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(201, {
      org: 'acme',
      repo: 'acme/app',
      sources: [{ ...liveAdvisory, id: 'ks_ghsa_repo' }],
    }),
  );

  render(<App initialPath='/knowledge' />);
  await screen.findByRole('link', { name: 'q3-2025-assessment.pdf' });

  await user.type(screen.getByLabelText(/connect github org/i), 'acme');
  await user.click(screen.getByRole('button', { name: /index advisories/i }));

  expect(
    await screen.findByRole('link', { name: 'SQL injection in oldpkg' }),
  ).toBeInTheDocument();
  const cited = screen.getByRole('region', { name: /cited page/i });
  expect(cited).toHaveTextContent('GHSA-aaaa-bbbb-cccc');
  expect(cited).not.toHaveTextContent('page 1');
  expect(fetchMock).toHaveBeenCalledTimes(2);
  const [path, init] = fetchMock.mock.calls[1];
  expect(path).toBe('/knowledge/github-advisories');
  expect(init.method).toBe('POST');
  expect(JSON.parse(init.body as string)).toEqual({ org: 'acme' });

  await user.type(screen.getByLabelText(/advisory repo/i), 'acme/app');
  await user.click(screen.getByRole('button', { name: /index advisories/i }));
  expect(fetchMock).toHaveBeenCalledTimes(3);
  const [repoPath, repoInit] = fetchMock.mock.calls[2];
  expect(repoPath).toBe('/knowledge/github-advisories');
  expect(JSON.parse(repoInit.body as string)).toEqual({
    org: 'acme',
    repo: 'acme/app',
  });

  await user.selectOptions(screen.getByLabelText(/kind/i), 'github_advisory');
  expect(
    screen.queryByRole('link', { name: 'q3-2025-assessment.pdf' }),
  ).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(3);
});

test('empty org submit does not POST', async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );

  render(<App initialPath='/knowledge' />);
  await screen.findByRole('link', { name: 'q3-2025-assessment.pdf' });

  await user.click(screen.getByRole('button', { name: /index advisories/i }));
  await user.type(screen.getByLabelText(/advisory repo/i), 'acme/app');
  await user.click(screen.getByRole('button', { name: /index advisories/i }));

  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(fetchMock.mock.calls[0][0]).toBe('/knowledge');
});

test('advisory index from a filtered PDF view opens the new advisory', async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(201, { org: 'acme', repo: null, sources: [liveAdvisory] }),
  );

  render(<App initialPath='/knowledge?source=ks_live' />);
  await screen.findByRole('link', { name: 'q3-2025-assessment.pdf' });

  await user.selectOptions(screen.getByLabelText(/kind/i), 'pdf');
  await user.type(screen.getByLabelText(/connect github org/i), 'acme');
  await user.click(screen.getByRole('button', { name: /index advisories/i }));

  expect(
    await screen.findByRole('link', { name: 'SQL injection in oldpkg' }),
  ).toBeInTheDocument();
  const cited = screen.getByRole('region', { name: /cited page/i });
  expect(cited).toHaveTextContent('GHSA-aaaa-bbbb-cccc');
  expect(cited).not.toHaveTextContent('reachable without a session');
  expect(cited).not.toHaveTextContent('page 1');
  expect(fetchMock).toHaveBeenCalledTimes(2);
  expect(fetchMock.mock.calls[0][0]).toBe('/knowledge');
  expect(fetchMock.mock.calls[1][0]).toBe('/knowledge/github-advisories');
});

test('Index advisories is disabled while the POST is pending', async () => {
  const user = userEvent.setup();
  let finishPost: (value: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    finishPost = resolve;
  });
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );
  fetchMock.mockReturnValueOnce(pending);

  render(<App initialPath='/knowledge' />);
  await screen.findByRole('link', { name: 'q3-2025-assessment.pdf' });

  await user.type(screen.getByLabelText(/connect github org/i), 'acme');
  const button = screen.getByRole('button', { name: /index advisories/i });
  await user.click(button);

  expect(button).toBeDisabled();
  finishPost!(
    new Response(
      JSON.stringify({ org: 'acme', repo: null, sources: [liveAdvisory] }),
      { status: 201, headers: { 'Content-Type': 'application/json' } },
    ),
  );
  expect(
    await screen.findByRole('link', { name: 'SQL injection in oldpkg' }),
  ).toBeInTheDocument();
  expect(
    screen.getByRole('button', { name: /index advisories/i }),
  ).toBeEnabled();
});

test('a failed advisory POST keeps the PDF fixture and raises alert', async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(503, { error: 'unavailable', detail: 'db locked' }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(502, {
      error: 'upstream',
      detail: 'github advisories failed',
    }),
  );

  render(<App initialPath='/knowledge' />);
  expect(
    await screen.findByRole('link', { name: 'v1-idor-assessment.pdf' }),
  ).toBeInTheDocument();

  await user.type(screen.getByLabelText(/connect github org/i), 'acme');
  await user.click(screen.getByRole('button', { name: /index advisories/i }));

  const alerts = await screen.findAllByRole('alert');
  expect(alerts.some((node) => node.textContent?.includes('upstream'))).toBe(
    true,
  );
  expect(
    screen.getByRole('link', { name: 'v1-idor-assessment.pdf' }),
  ).toBeInTheDocument();
});
