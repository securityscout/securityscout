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

const RUNS = [
  { id: "run_a", status: "running" },
  { id: "run_b", status: "running" },
];

function mockRoutes(cancelStatus: (id: string) => number) {
  return vi.fn((url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method === "GET" && url.endsWith("/engagements")) {
      return jsonResponse(200, { engagements: [{ id: "eng_1", name: "acme-web", org: "acme" }] });
    }
    if (method === "GET" && url.endsWith("/engagements/eng_1/runs")) {
      return jsonResponse(200, { runs: RUNS });
    }
    const cancelMatch = /\/runs\/([^/]+)\/cancel$/.exec(url);
    if (method === "POST" && cancelMatch) {
      const status = cancelStatus(cancelMatch[1]);
      if (status >= 400) {
        return jsonResponse(status, { error: "conflict", detail: `cannot cancel ${cancelMatch[1]}` });
      }
      return jsonResponse(200, { id: cancelMatch[1], status: "cancelled" });
    }
    return jsonResponse(404, { error: "not_found", detail: "" });
  });
}

let fetchMock: ReturnType<typeof mockRoutes>;

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("Kill switch POSTs cancel for two mocked running runs", async () => {
  const user = userEvent.setup();
  fetchMock = mockRoutes(() => 200);
  vi.stubGlobal("fetch", fetchMock);
  render(<App initialPath="/" />);

  await user.click(screen.getByRole("button", { name: /kill switch/i }));

  const cancelCalls = fetchMock.mock.calls.filter(
    ([, init]) => (init as RequestInit | undefined)?.method === "POST",
  );
  expect(cancelCalls).toHaveLength(2);
  const cancelledIds = cancelCalls
    .map(([url]) => /\/runs\/([^/]+)\/cancel$/.exec(url as string)?.[1])
    .sort();
  expect(cancelledIds).toEqual(["run_a", "run_b"]);
});

test("one failed cancel does not abort the rest and surfaces an alert", async () => {
  const user = userEvent.setup();
  fetchMock = mockRoutes((id) => (id === "run_a" ? 409 : 200));
  vi.stubGlobal("fetch", fetchMock);
  render(<App initialPath="/" />);

  await user.click(screen.getByRole("button", { name: /kill switch/i }));

  const cancelCalls = fetchMock.mock.calls.filter(
    ([, init]) => (init as RequestInit | undefined)?.method === "POST",
  );
  expect(cancelCalls).toHaveLength(2);
  expect(await screen.findByRole("alert")).toHaveTextContent("cannot cancel run_a");
});

test("both cancels failing surfaces both errors, not just the last one", async () => {
  const user = userEvent.setup();
  fetchMock = mockRoutes(() => 409);
  vi.stubGlobal("fetch", fetchMock);
  render(<App initialPath="/" />);

  await user.click(screen.getByRole("button", { name: /kill switch/i }));

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("cannot cancel run_a");
  expect(alert).toHaveTextContent("cannot cancel run_b");
});
