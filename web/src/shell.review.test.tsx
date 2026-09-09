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

test("accept posts review and publishes the banner", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { id: "f1", status: "published" }),
  );
  render(<App initialPath="/findings/f1" />);

  await user.click(screen.getByRole("button", { name: /^accept$/i }));

  expect(fetchMock).toHaveBeenCalledWith(
    "/findings/f1/review",
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ action: "accept" }),
    }),
  );
  expect(screen.getByRole("banner")).toHaveTextContent("published");
  expect(screen.getByRole("banner")).toHaveTextContent("High");
  expect(screen.getByRole("banner")).toHaveTextContent("CWE-89");
});

test("reject and accept-risk post their actions", async () => {
  const user = userEvent.setup();
  fetchMock
    .mockReturnValueOnce(jsonResponse(200, { id: "f1", status: "done" }))
    .mockReturnValueOnce(jsonResponse(200, { id: "f1", status: "done" }));
  render(<App initialPath="/findings/f1" />);

  await user.click(screen.getByRole("button", { name: /^reject$/i }));
  await user.click(screen.getByRole("button", { name: /accept.risk/i }));

  expect(fetchMock).toHaveBeenNthCalledWith(
    1,
    "/findings/f1/review",
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ action: "reject" }),
    }),
  );
  expect(fetchMock).toHaveBeenNthCalledWith(
    2,
    "/findings/f1/review",
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ action: "accept_risk" }),
    }),
  );
});

test("replay posts and shows queued without passed", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(202, { finding_id: "f1", replay_status: "queued" }),
  );
  render(<App initialPath="/findings/f1" />);

  await user.click(screen.getByRole("button", { name: /^replay$/i }));

  expect(fetchMock).toHaveBeenCalledWith(
    "/findings/f1/replay",
    expect.objectContaining({ method: "POST" }),
  );
  expect(screen.getByRole("status")).toHaveTextContent("queued");
  expect(document.body).not.toHaveTextContent(/passed/i);
});

test("r on the case file posts replay", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(202, { finding_id: "f1", replay_status: "queued" }),
  );
  render(<App initialPath="/findings/f1" />);

  await user.keyboard("r");

  expect(fetchMock).toHaveBeenCalledWith(
    "/findings/f1/replay",
    expect.objectContaining({ method: "POST" }),
  );
});

test("accept on done finding shows illegal_transition", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(409, {
      error: "illegal_transition",
      detail: "cannot transition from done to published",
    }),
  );
  render(<App initialPath="/findings/f2" />);

  await user.click(screen.getByRole("button", { name: /^accept$/i }));

  const alert = screen.getByRole("alert");
  expect(alert).toHaveTextContent("illegal_transition");
  expect(alert).toHaveTextContent("cannot transition from done to published");
  expect(screen.getByRole("banner")).toHaveTextContent("done");
});

test("review error does not follow the next finding", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(409, {
      error: "illegal_transition",
      detail: "cannot transition from done to published",
    }),
  );
  render(<App initialPath="/findings/f2" />);

  await user.click(screen.getByRole("button", { name: /^accept$/i }));
  expect(screen.getByRole("alert")).toBeInTheDocument();

  await user.click(screen.getByRole("link", { name: /^findings$/i }));
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.getByRole("banner")).toHaveTextContent("needs_review");
});

test("review clears replay status", async () => {
  const user = userEvent.setup();
  fetchMock
    .mockReturnValueOnce(
      jsonResponse(202, { finding_id: "f1", replay_status: "queued" }),
    )
    .mockReturnValueOnce(jsonResponse(200, { id: "f1", status: "published" }));
  render(<App initialPath="/findings/f1" />);

  await user.click(screen.getByRole("button", { name: /^replay$/i }));
  expect(screen.getByRole("status")).toHaveTextContent("queued");

  await user.click(screen.getByRole("button", { name: /^accept$/i }));
  expect(screen.queryByRole("status")).toBeNull();
  expect(screen.getByRole("banner")).toHaveTextContent("published");
});
