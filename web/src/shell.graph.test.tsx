import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("live GET renders the hop and both finding labels", async () => {
  fetchMock.mockReturnValueOnce(liveGraph());

  render(<App initialPath="/graph/eng_1" />);

  expect(
    await screen.findByRole("link", { name: "app/auth.py:34" }),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("link", { name: "app/admin.py:8" }),
  ).toBeInTheDocument();
  expect(screen.getByRole("region", { name: /attack graph/i })).toHaveTextContent(
    "session",
  );
  expect(screen.getByRole("heading")).toHaveTextContent("Graph");
  expect(fetchMock).toHaveBeenCalledWith(
    "/engagements/eng_1/graph",
    expect.objectContaining({ method: "GET" }),
  );
});

test("clicking a node opens that finding's case file", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(liveGraph());

  render(<App initialPath="/graph/eng_1" />);
  const node = await screen.findByRole("link", { name: "app/admin.py:8" });
  expect(node).toHaveAttribute("href", "/findings/f2");

  await user.click(node);

  expect(
    await screen.findByRole("button", { name: /^replay$/i }),
  ).toBeInTheDocument();
  expect(screen.getByRole("region", { name: /source/i })).toHaveTextContent(
    "src/b.py:2",
  );
});

test("empty 200 clears the fixture path", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { engagement_id: "eng_1", nodes: [], hops: [] }),
  );

  render(<App initialPath="/graph/eng_1" />);

  await vi.waitFor(() => {
    expect(screen.queryByRole("link", { name: "src/a.py:1" })).toBeNull();
  });
  expect(screen.getByRole("region", { name: /attack graph/i })).toHaveTextContent(
    /no chain hops yet/i,
  );
  expect(screen.queryByRole("alert")).toBeNull();
});

test("!ok keeps the fixture path and raises an alert", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(503, { error: "unavailable", detail: "db locked" }),
  );

  render(<App initialPath="/graph/eng_1" />);

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("unavailable");
  expect(alert).toHaveTextContent("db locked");
  expect(screen.getByRole("link", { name: "src/a.py:1" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "src/b.py:2" })).toBeInTheDocument();
  expect(screen.getByRole("region", { name: /attack graph/i })).toHaveTextContent(
    "session",
  );
});

test("thrown fetch keeps the fixture path and raises an alert", async () => {
  fetchMock.mockRejectedValueOnce(new TypeError("network down"));

  render(<App initialPath="/graph/eng_1" />);

  expect(await screen.findByRole("alert")).toHaveTextContent("unavailable");
  expect(screen.getByRole("link", { name: "src/a.py:1" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "src/b.py:2" })).toBeInTheDocument();
});
