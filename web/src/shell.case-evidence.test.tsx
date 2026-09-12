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

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("the proof pane shows the artifact uri and the replay command", () => {
  render(<App initialPath="/findings/f1" />);

  const proof = screen.getByRole("region", { name: /^proof$/i });
  expect(proof).toHaveTextContent("harness");
  expect(proof).toHaveTextContent("poc/f1.py");
  expect(proof).toHaveTextContent("pytest poc/f1.py");

  expect(screen.getByRole("region", { name: /^knowledge$/i })).toBeEmptyDOMElement();
  expect(screen.getByRole("button", { name: /^replay$/i })).toBeInTheDocument();
  expect(fetchMock).not.toHaveBeenCalled();
});

test("source and proof share the evidence row of the case file", () => {
  render(<App initialPath="/findings/f1" />);

  const source = screen.getByRole("region", { name: /^source$/i });
  const proof = screen.getByRole("region", { name: /^proof$/i });

  expect(source).toHaveTextContent("src/a.py:1");
  expect(source.closest(".case-file")).not.toBeNull();
  expect(proof.parentElement).toBe(source.parentElement);
  expect(source.nextElementSibling).toBe(proof);
});

test("r still posts the replay while the evidence stays on the page", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { finding_id: "f1", replay_status: "passed" }),
  );
  render(<App initialPath="/findings/f1" />);

  await user.keyboard("r");

  expect(fetchMock).toHaveBeenCalledWith(
    "/findings/f1/replay",
    expect.objectContaining({ method: "POST" }),
  );
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(await screen.findByRole("status")).toHaveTextContent("passed");
  expect(screen.getByRole("region", { name: /^proof$/i })).toHaveTextContent(
    "pytest poc/f1.py",
  );
});
