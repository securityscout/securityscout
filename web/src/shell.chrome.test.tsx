import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, test } from 'vitest';

import { App } from './app';

afterEach(() => {
  cleanup();
});

test('chrome meter shows the monthly remaining cap', () => {
  render(<App />);

  const meter = screen.getByRole('meter', { name: /budget remaining/i });
  expect(meter).toHaveAttribute('aria-valuemin', '0');
  expect(meter).toHaveAttribute('aria-valuemax', '200');
  expect(meter).toHaveAttribute('aria-valuenow', '200');
  expect(meter).toHaveTextContent('200');
});

test('rail marks the current destination', () => {
  render(<App initialPath='/knowledge' />);

  const rail = screen.getByRole('navigation', { name: /rail/i });
  expect(
    within(rail).getByRole('link', { name: /^knowledge$/i }),
  ).toHaveAttribute('aria-current', 'page');
  expect(
    within(rail).getByRole('link', { name: /^engagements$/i }),
  ).not.toHaveAttribute('aria-current', 'page');
});

test('palette search filters destinations', async () => {
  const user = userEvent.setup();
  render(<App />);

  await user.keyboard('{Meta>}k{/Meta}');
  const dialog = screen.getByRole('dialog', { name: /command/i });
  const search = within(dialog).getByRole('textbox');
  expect(search).toHaveFocus();

  await user.type(search, 'cal');
  expect(
    within(dialog).getByRole('link', { name: /^calibration$/i }),
  ).toBeInTheDocument();
  expect(
    within(dialog).queryByRole('link', { name: /^engagements$/i }),
  ).toBeNull();

  await user.clear(search);
  await user.type(search, 'zzz');
  expect(dialog).toHaveTextContent('No matching destinations.');
  expect(within(dialog).queryByRole('link')).toBeNull();
});
