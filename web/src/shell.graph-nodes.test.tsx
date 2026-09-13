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

function liveGraph(): Promise<Response> {
  return jsonResponse(200, {
    engagement_id: "eng_1",
    nodes: [
      { id: "f1", kind: "finding", label: "app/auth.py:34" },
      { id: "f2", kind: "finding", label: "app/admin.py:8" },
    ],
    hops: [
      {
        id: "hop_1",
        from_id: "f1",
        to_id: "f2",
        kind: "session",
        evidence_uri: "tests/fixtures/graph/transcripts/abc.json",
      },
    ],
  });
}

function nodeTexts(): string[] {
  const list = screen.getByRole("list", { name: /nodes/i });
  return within(list)
    .queryAllByRole("listitem")
    .map((item) => item.textContent ?? "");
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

test("live nodes are listitem text and the hop keeps the only links", async () => {
  fetchMock.mockReturnValueOnce(liveGraph());

  render(<App initialPath="/graph/eng_1" />);

  await screen.findByRole("link", { name: "app/auth.py:34" });
  expect(nodeTexts()).toEqual(["app/auth.py:34", "app/admin.py:8"]);
  const nodes = screen.getByRole("list", { name: /nodes/i });
  expect(within(nodes).queryAllByRole("link")).toHaveLength(0);
  for (const label of ["app/auth.py:34", "app/admin.py:8"]) {
    expect(screen.getAllByRole("link", { name: label })).toHaveLength(1);
  }
  expect(screen.getAllByRole("heading")).toHaveLength(1);
  expect(fetchMock).toHaveBeenCalledWith(
    "/engagements/eng_1/graph",
    expect.objectContaining({ method: "GET" }),
  );
});

test("empty 200 leaves the nodes list present and empty", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { engagement_id: "eng_1", nodes: [], hops: [] }),
  );

  render(<App initialPath="/graph/eng_1" />);

  await vi.waitFor(() => {
    expect(nodeTexts()).toEqual([]);
  });
});

test("!ok keeps the fixture nodes beside the alert", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(503, { error: "unavailable", detail: "db locked" }),
  );

  render(<App initialPath="/graph/eng_1" />);

  await screen.findByRole("alert");
  expect(nodeTexts()).toEqual(["src/a.py:1", "src/b.py:2"]);
});
