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

test("/ GETs /engagements", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, { engagements: [] }));

  render(<App initialPath="/" />);

  await vi.waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      "/engagements",
      expect.objectContaining({ method: "GET" }),
    );
  });
});

test("org submit POSTs /engagements/import and the row appears", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(jsonResponse(200, { engagements: [] }));
  render(<App initialPath="/" />);
  await screen.findByRole("row", { name: /No GitHub token/i });

  fetchMock.mockReturnValueOnce(
    jsonResponse(201, {
      id: "eng_2",
      name: "acme",
      org: "acme",
      policy_json: {},
      created_at: "2026-01-01T00:00:00Z",
      repos: [{ locator: "acme/app" }],
    }),
  );

  await user.type(screen.getByLabelText("Org"), "acme");
  await user.click(screen.getByRole("button", { name: /^add$/i }));

  expect(fetchMock).toHaveBeenCalledWith(
    "/engagements/import",
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ org: "acme" }),
    }),
  );
  expect(await screen.findByRole("row", { name: /acme/i })).toBeInTheDocument();
});

test("repo URL submit POSTs /engagements, not import", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(jsonResponse(200, { engagements: [] }));
  render(<App initialPath="/" />);
  await screen.findByRole("row", { name: /No GitHub token/i });

  fetchMock.mockReturnValueOnce(
    jsonResponse(201, {
      id: "eng_3",
      name: "app",
      org: "acme",
      policy_json: {},
      created_at: "2026-01-01T00:00:00Z",
    }),
  );

  await user.type(
    screen.getByLabelText("Repo URL"),
    "https://github.com/acme/app",
  );
  await user.click(screen.getByRole("button", { name: /^add$/i }));

  expect(fetchMock).toHaveBeenCalledWith(
    "/engagements",
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ name: "app", org: "acme", policy_json: {} }),
    }),
  );
  expect(fetchMock).not.toHaveBeenCalledWith(
    "/engagements/import",
    expect.anything(),
  );
});

test("502 upstream on import shows an alert", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(jsonResponse(200, { engagements: [] }));
  render(<App initialPath="/" />);
  await screen.findByRole("row", { name: /No GitHub token/i });

  fetchMock.mockReturnValueOnce(
    jsonResponse(502, { error: "upstream", detail: "gh api rc=1" }),
  );

  await user.type(screen.getByLabelText("Org"), "acme");
  await user.click(screen.getByRole("button", { name: /^add$/i }));

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("upstream");
});
