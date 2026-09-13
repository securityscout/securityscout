import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./app";

const cssPath = join(dirname(fileURLToPath(import.meta.url)), "index.css");

function jsonResponse(status: number, body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

const fetchMock = vi.fn();
const eventSourceMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  eventSourceMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubGlobal("EventSource", eventSourceMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("the live status rule animates a keyframe that index.css defines", () => {
  const css = readFileSync(cssPath, "utf8");

  const defined = [...css.matchAll(/@keyframes\s+([\w-]+)/g)].map((m) => m[1]);
  const rules = [...css.matchAll(/\[data-live[^{]*\{([^}]*)\}/g)].map(
    (m) => m[1],
  );
  expect(rules, "index.css has no [data-live] rule").not.toHaveLength(0);

  // Any [data-live] rule may name the keyframe, in either the shorthand or
  // animation-name, and the shorthand does not pin where the name sits.
  const animated = rules.filter((body) =>
    /animation(-name)?:/.test(body) &&
    defined.some((name) => new RegExp(`\\b${name}\\b`).test(body)),
  );
  expect(
    animated,
    `no [data-live] rule animates a defined keyframe (defined: ${defined.join(", ") || "none"})`,
  ).not.toHaveLength(0);
});

test("the run viewer keeps its three labeled regions", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      id: "run_1",
      engagement_id: "eng_1",
      status: "queued",
    }),
  );
  render(<App initialPath="/engagements/eng_1/runs/run_1" />);

  expect(screen.getByRole("heading", { name: /run/i })).toBeInTheDocument();
  for (const name of [/^playbook steps$/i, /^evidence timeline$/i, /^agent graph$/i]) {
    expect(screen.getByRole("region", { name })).toBeInTheDocument();
  }

  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
  expect(eventSourceMock).not.toHaveBeenCalled();
});

test("a running run marks the status live and lists agents beside handoffs", async () => {
  // A running run keeps polling, so every call needs its own Response — a
  // shared one has a spent body by the second read.
  fetchMock.mockImplementation(() =>
    jsonResponse(200, {
      id: "run_1",
      engagement_id: "eng_1",
      status: "running",
      spans: [
        {
          id: "s1",
          agent: "scout",
          tool: "grep",
          args_hash: "aaaaaaaabbbb",
          result_sha256: "ccccccccdddd",
          t: "2026-09-12T10:00:00Z",
        },
        {
          id: "s2",
          agent: "prover",
          tool: "pytest",
          args_hash: "eeeeeeeeffff",
          result_sha256: "111111112222",
          t: "2026-09-12T10:00:04Z",
        },
      ],
    }),
  );
  render(<App initialPath="/engagements/eng_1/runs/run_1" />);

  await waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent("running"),
  );
  expect(screen.getByRole("status")).toHaveAttribute("data-live", "true");

  const graph = screen.getByRole("region", { name: /^agent graph$/i });
  const agents = screen.getByRole("list", { name: /^agents$/i });
  const edges = screen.getByRole("list", { name: /^handoffs$/i });
  expect(graph).toContainElement(agents);
  expect(graph).toContainElement(edges);
  expect(agents).toHaveTextContent("scout");
  expect(edges).toHaveTextContent("scout → prover");

  const timeline = screen.getByRole("region", { name: /^evidence timeline$/i });
  expect(timeline).toHaveTextContent("aaaaaaaa → cccccccc");

  expect(eventSourceMock).not.toHaveBeenCalled();
  for (const call of fetchMock.mock.calls) {
    expect(call[0]).not.toMatch(/\/events$/);
  }
});
