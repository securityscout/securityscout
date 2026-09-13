import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./app";

const POLICIES = {
  scope: { repos: [], hosts: [] },
  blast_radius: "safe",
  budget: { monthly_usd: 200, per_finding_usd: 200 },
  models: {},
  auto_publish: false,
};

function jsonResponse(status: number, body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

const fetchMock = vi.fn();

function putCalls() {
  return fetchMock.mock.calls.filter((call) => call[1]?.method === "PUT");
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("/policies GETs /policies and fills the five fields", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, POLICIES));

  render(<App initialPath="/policies" />);

  expect(
    screen.getByRole("heading", { level: 1, name: /^policies$/i }),
  ).toBeInTheDocument();
  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled());
  expect(fetchMock.mock.calls[0][0]).toBe("/policies");
  expect(fetchMock.mock.calls[0][1]).toEqual(
    expect.objectContaining({ method: "GET" }),
  );

  const scope = await screen.findByRole("textbox", { name: /scope/i });
  expect(scope).toHaveValue(JSON.stringify(POLICIES.scope, null, 2));
  expect(screen.getByRole("textbox", { name: /budget/i })).toHaveValue(
    JSON.stringify(POLICIES.budget, null, 2),
  );
  expect(screen.getByRole("textbox", { name: /models/i })).toHaveValue(
    JSON.stringify(POLICIES.models, null, 2),
  );
  expect(screen.getByLabelText(/blast radius/i)).toHaveValue("safe");
  expect(screen.getByLabelText(/auto.publish/i)).not.toBeChecked();
});

test("blast radius select offers safe, intrusive and destructive", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, POLICIES));
  render(<App initialPath="/policies" />);

  const select = await screen.findByLabelText(/blast radius/i);
  expect(
    [...select.querySelectorAll("option")].map((option) => option.value),
  ).toEqual(["safe", "intrusive", "destructive"]);
});

test("save PUTs all five keys with the parsed blast radius", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(jsonResponse(200, POLICIES));
  render(<App initialPath="/policies" />);
  await screen.findByRole("textbox", { name: /scope/i });

  const saved = { ...POLICIES, blast_radius: "intrusive" };
  fetchMock.mockReturnValueOnce(jsonResponse(200, saved));

  await user.selectOptions(
    screen.getByLabelText(/blast radius/i),
    "intrusive",
  );
  await user.click(screen.getByRole("button", { name: /save/i }));

  await vi.waitFor(() => expect(putCalls()).toHaveLength(1));
  const [path, init] = putCalls()[0];
  expect(path).toBe("/policies");
  expect(JSON.parse(init.body)).toEqual(saved);

  expect(screen.getByLabelText(/blast radius/i)).toHaveValue("intrusive");
});

test("invalid JSON alerts invalid_request and does not PUT", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(jsonResponse(200, POLICIES));
  render(<App initialPath="/policies" />);
  const scope = await screen.findByRole("textbox", { name: /scope/i });

  await user.clear(scope);
  await user.type(scope, "{{ not json");
  await user.click(screen.getByRole("button", { name: /save/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent("invalid_request");
  expect(putCalls()).toHaveLength(0);
});

test("a failed GET shows the error alert", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(503, { error: "unavailable", detail: "policies offline" }),
  );

  render(<App initialPath="/policies" />);

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("unavailable");
  expect(alert).toHaveTextContent("policies offline");
});

test("/ still GETs /engagements first", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, { engagements: [] }));

  render(<App initialPath="/" />);

  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled());
  expect(fetchMock.mock.calls[0][0]).toBe("/engagements");
  expect(fetchMock).not.toHaveBeenCalledWith("/policies", expect.anything());
});
