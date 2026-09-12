import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./app";

function jsonResponse(status: number, body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("heading is a level-1 Engagements with the page-title class, above the form", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, { engagements: [] }));
  render(<App initialPath="/" />);

  const heading = await screen.findByRole("heading", {
    level: 1,
    name: /^engagements$/i,
  });
  expect(heading).toHaveClass("page-title");

  const page = heading.parentElement;
  expect(page?.firstElementChild).toBe(heading);
  expect(page?.querySelector("form")).not.toBeNull();
});

test("table headers are ID, Name, Org, Env and data rows carry an empty Env cell", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      engagements: [{ id: "eng_1", name: "acme-web", org: "acme" }],
    }),
  );
  render(<App initialPath="/" />);

  const headerRow = (await screen.findAllByRole("columnheader")).map(
    (cell) => cell.textContent,
  );
  expect(headerRow).toEqual(["ID", "Name", "Org", "Env"]);

  const row = await screen.findByRole("row", { name: /acme-web/i });
  const cells = within(row).getAllByRole("cell");
  expect(cells).toHaveLength(4);
  expect(cells[3]).toHaveTextContent("");
});

test("empty state spans all four columns", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, { engagements: [] }));
  render(<App initialPath="/" />);

  const row = await screen.findByRole("row", { name: /No GitHub token/i });
  const cell = within(row).getByRole("cell");
  expect(cell).toHaveAttribute("colspan", "4");
});

test("Org, Repo URL and Add stay unchanged", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, { engagements: [] }));
  render(<App initialPath="/" />);

  await screen.findByRole("row", { name: /No GitHub token/i });
  expect(screen.getByLabelText("Org")).toBeInTheDocument();
  expect(screen.getByLabelText("Repo URL")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /^add$/i })).toBeInTheDocument();
});
