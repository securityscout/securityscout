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

test("accept with a ticket url renders the Ticket pane and makes no extra fetch", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      id: "f1",
      status: "published",
      tickets: [
        {
          id: "t1",
          sink: "github",
          external_id: "1",
          url: "https://github.com/acme/app/issues/1",
          published_at: "2026-09-11T00:00:00+00:00",
        },
      ],
    }),
  );
  render(<App initialPath="/findings/f1" />);

  await user.click(screen.getByRole("button", { name: /^accept$/i }));

  const pane = screen.getByRole("region", { name: /^ticket$/i });
  expect(pane).toHaveTextContent("https://github.com/acme/app/issues/1");
  expect(screen.getByRole("banner")).toHaveTextContent("published");
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("accept with no tickets leaves the Ticket pane empty", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { id: "f1", status: "published", tickets: [] }),
  );
  render(<App initialPath="/findings/f1" />);

  await user.click(screen.getByRole("button", { name: /^accept$/i }));

  const pane = screen.getByRole("region", { name: /^ticket$/i });
  expect(pane).toHaveTextContent("");
  expect(screen.getByRole("banner")).toHaveTextContent("published");
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("no GET /findings/f1 fires on mount", async () => {
  render(<App initialPath="/findings/f1" />);

  expect(fetchMock).not.toHaveBeenCalled();
});
