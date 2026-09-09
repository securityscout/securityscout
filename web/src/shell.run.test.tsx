import { cleanup, render, screen, waitFor } from "@testing-library/react";
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
  vi.useRealTimers();
});

test("renders run_1 via GET /runs/{id}, never touches /events or EventSource", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      id: "run_1",
      engagement_id: "eng_1",
      status: "queued",
    }),
  );
  render(<App initialPath="/engagements/eng_1/runs/run_1" />);

  expect(
    screen.getByRole("heading", { name: /Run run_1/ }),
  ).toBeInTheDocument();

  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
  expect(fetchMock).toHaveBeenCalledWith(
    "/runs/run_1",
    expect.objectContaining({ method: "GET" }),
  );
  for (const call of fetchMock.mock.calls) {
    expect(call[0]).not.toMatch(/\/events$/);
  }
  expect(eventSourceMock).not.toHaveBeenCalled();
});

test("queued status shows no live pulse and does not poll", async () => {
  vi.useFakeTimers();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      id: "run_1",
      engagement_id: "eng_1",
      status: "queued",
    }),
  );
  render(<App initialPath="/engagements/eng_1/runs/run_1" />);

  await vi.waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent("queued"),
  );
  expect(screen.getByRole("status")).not.toHaveAttribute("data-live");

  const callsBefore = fetchMock.mock.calls.length;
  await vi.advanceTimersByTimeAsync(1000);
  expect(fetchMock.mock.calls.length).toBe(callsBefore);
});

test("window focus refetches even while queued", async () => {
  fetchMock
    .mockReturnValueOnce(
      jsonResponse(200, {
        id: "run_1",
        engagement_id: "eng_1",
        status: "queued",
      }),
    )
    .mockReturnValueOnce(
      jsonResponse(200, {
        id: "run_1",
        engagement_id: "eng_1",
        status: "queued",
      }),
    );
  render(<App initialPath="/engagements/eng_1/runs/run_1" />);

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  window.dispatchEvent(new Event("visibilitychange"));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
});

test("running status polls every 1s and stops once done", async () => {
  vi.useFakeTimers();
  fetchMock
    .mockReturnValueOnce(
      jsonResponse(200, {
        id: "run_1",
        engagement_id: "eng_1",
        status: "running",
      }),
    )
    .mockReturnValueOnce(
      jsonResponse(200, {
        id: "run_1",
        engagement_id: "eng_1",
        status: "running",
      }),
    )
    .mockReturnValueOnce(
      jsonResponse(200, {
        id: "run_1",
        engagement_id: "eng_1",
        status: "done",
      }),
    );
  render(<App initialPath="/engagements/eng_1/runs/run_1" />);

  await vi.waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent("running"),
  );
  expect(screen.getByRole("status")).toHaveAttribute("data-live", "true");

  await vi.advanceTimersByTimeAsync(1000);
  expect(fetchMock).toHaveBeenCalledTimes(2);

  await vi.advanceTimersByTimeAsync(1000);
  await vi.waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent("done"),
  );
  expect(screen.getByRole("status")).not.toHaveAttribute("data-live");
  expect(fetchMock).toHaveBeenCalledTimes(3);

  const callsBefore = fetchMock.mock.calls.length;
  await vi.advanceTimersByTimeAsync(1000);
  expect(fetchMock.mock.calls.length).toBe(callsBefore);
});

test("404 after run_1 initialData keeps heading and last good status, shows alert", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(404, { error: "not_found", detail: "no such run" }),
  );
  render(<App initialPath="/engagements/eng_1/runs/run_1" />);

  expect(
    screen.getByRole("heading", { name: /Run run_1/ }),
  ).toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("queued");

  await waitFor(() => {
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("not_found");
    expect(alert).toHaveTextContent("no such run");
  });
  expect(screen.getByRole("status")).toHaveTextContent("queued");
});

test("unknown run id has no initialData and shows alert on failure", async () => {
  fetchMock.mockReturnValueOnce(Promise.reject(new Error("network down")));
  render(<App initialPath="/engagements/eng_1/runs/run_missing" />);

  expect(
    screen.getByRole("heading", { name: /Run run_missing/ }),
  ).toBeInTheDocument();

  await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
  expect(fetchMock).toHaveBeenCalledWith(
    "/runs/run_missing",
    expect.objectContaining({ method: "GET" }),
  );
});
