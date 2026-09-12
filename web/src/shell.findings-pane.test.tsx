import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./app";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockRejectedValue(new TypeError("network down"));
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function severityCell(name: RegExp): HTMLElement {
  const row = screen.getByRole("row", { name });
  return within(row).getAllByRole("cell")[1];
}

test("the findings title sits above the table and reuses .page-title", async () => {
  render(<App initialPath="/engagements/eng_1" />);
  await screen.findByRole("alert");

  const title = screen.getByRole("heading", { level: 1, name: /^findings$/i });
  expect(title).toHaveClass("page-title");

  const position = title.compareDocumentPosition(screen.getByRole("table"));
  expect(position & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

  expect(fetchMock.mock.calls[0][0]).toBe("/findings?engagement_id=eng_1");
});

test("rows group by rule without collapsing the finding rows", async () => {
  render(<App initialPath="/engagements/eng_1" />);
  await screen.findByRole("alert");

  expect(screen.getByRole("checkbox", { name: /group by rule/i })).toBeChecked();

  expect(screen.getAllByRole("row", { name: /f1/ })).toHaveLength(1);
  expect(screen.getAllByRole("row", { name: /f2/ })).toHaveLength(1);
  for (const header of ["ID", "Severity", "Class", "Location", "Status", "Rule"]) {
    expect(screen.getByRole("columnheader", { name: header })).toBeInTheDocument();
  }
});

test("the detail region follows j/k selection", async () => {
  const user = userEvent.setup();
  render(<App initialPath="/engagements/eng_1" />);
  await screen.findByRole("alert");

  const detail = screen.getByRole("region", { name: /^detail$/i });
  expect(detail).toHaveTextContent("src/a.py:1");
  expect(detail).toHaveTextContent("needs_review");

  await user.keyboard("j");

  expect(screen.getByRole("row", { name: /f2/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  expect(detail).toHaveTextContent("src/b.py:2");
  expect(detail).toHaveTextContent("done");
  expect(detail).not.toHaveTextContent("src/a.py:1");
});

test("severity cells carry the severity token", async () => {
  render(<App initialPath="/engagements/eng_1" />);
  await screen.findByRole("alert");

  expect(severityCell(/f1/)).toHaveTextContent("High");
  expect(severityCell(/f1/).getAttribute("style")).toContain(
    "--color-sev-high",
  );
  expect(severityCell(/f2/).getAttribute("style")).toContain(
    "--color-sev-medium",
  );
});
