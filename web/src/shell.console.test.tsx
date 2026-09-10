import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
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

const SPANS = [
  {
    id: "sp1",
    agent: "recon",
    tool: "read_file",
    args_hash: "aaaaaaaa11111111",
    result_sha256: "bbbbbbbb22222222",
    t: "2026-09-08T00:00:01+00:00",
  },
  {
    id: "sp2",
    agent: "hunter",
    tool: "http",
    args_hash: "cccccccc33333333",
    result_sha256: "dddddddd44444444",
    t: "2026-09-08T00:00:02+00:00",
  },
  {
    id: "sp3",
    agent: "recon",
    tool: "read_file",
    args_hash: "eeeeeeee55555555",
    result_sha256: "ffffffff66666666",
    t: "2026-09-08T00:00:03+00:00",
  },
];

function runBody(over: Record<string, unknown> = {}) {
  return {
    id: "run_1",
    engagement_id: "eng_1",
    mode: "triage",
    playbook: "web-app.v1",
    repo: "acme/app",
    sha: "deadbeef",
    target_url: null,
    status: "running",
    budget_spent_usd: 0,
    budget_limit_usd: null,
    started_at: "2026-09-08T00:00:00+00:00",
    ended_at: null,
    spans: [],
    ...over,
  };
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

function renderConsole() {
  render(<App initialPath="/engagements/eng_1/runs/run_1" />);
}

test("three columns render from one GET /runs/{id}", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, runBody({ status: "queued", spans: SPANS })),
  );
  renderConsole();

  const timeline = await screen.findByRole("region", {
    name: /evidence timeline/i,
  });
  const rows = await within(timeline).findAllByRole("listitem");
  expect(rows).toHaveLength(3);
  expect(rows[0]).toHaveTextContent("recon");
  expect(rows[0]).toHaveTextContent("read_file");
  expect(rows[0]).toHaveTextContent("aaaaaaaa");
  expect(rows[0]).toHaveTextContent("bbbbbbbb");
  expect(rows[2]).toHaveTextContent("eeeeeeee");

  const steps = screen.getByRole("region", { name: /playbook/i });
  expect(steps).toHaveTextContent("web-app.v1");
  expect(within(steps).getByText("queued")).toHaveAttribute(
    "aria-current",
    "step",
  );

  const graph = screen.getByRole("region", { name: /agent graph/i });
  const agents = within(graph).getByRole("list", { name: /agents/i });
  expect(within(agents).getByText(/recon/)).toHaveTextContent("2");
  expect(within(agents).getByText(/hunter/)).toHaveTextContent("1");
  const handoffs = within(graph).getByRole("list", { name: /handoffs/i });
  expect(handoffs).toHaveTextContent("recon → hunter");
  expect(handoffs).toHaveTextContent("hunter → recon");

  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("no spans renders operational empty states", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, runBody({ status: "queued" })));
  renderConsole();

  const timeline = await screen.findByRole("region", {
    name: /evidence timeline/i,
  });
  expect(timeline).toHaveTextContent(/no tool spans yet/i);
  expect(within(timeline).queryAllByRole("listitem")).toHaveLength(0);
  expect(
    screen.getByRole("region", { name: /agent graph/i }),
  ).toHaveTextContent(/no agents have run/i);
});

test("a single-agent run lists the agent and says there are no handoffs", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(
      200,
      runBody({ status: "queued", spans: [SPANS[0], SPANS[2]] }),
    ),
  );
  renderConsole();

  const graph = await screen.findByRole("region", { name: /agent graph/i });
  await waitFor(() =>
    expect(within(graph).getByRole("list", { name: /agents/i })).toBeInTheDocument(),
  );
  expect(
    within(graph).queryByRole("list", { name: /handoffs/i }),
  ).not.toBeInTheDocument();
  expect(graph).toHaveTextContent(/no handoffs/i);
});

test("budget meter takes max from budget_limit_usd", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(
      200,
      runBody({ status: "queued", budget_spent_usd: 3.5, budget_limit_usd: 12.5 }),
    ),
  );
  renderConsole();

  const meter = await screen.findByRole("progressbar", { name: /budget/i });
  await waitFor(() => expect(meter).toHaveAttribute("max", "12.5"));
  expect(meter).toHaveAttribute("value", "3.5");
});

test("budget meter is indeterminate without a limit", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, runBody({ status: "queued", budget_spent_usd: 3.5 })),
  );
  renderConsole();

  await screen.findByText(/3\.50 USD spent/);
  const meter = screen.getByRole("progressbar", { name: /budget/i });
  expect(meter).not.toHaveAttribute("max");
  expect(meter).not.toHaveAttribute("value");
});

test("Kill run posts cancel, refetches, then disables", async () => {
  const user = userEvent.setup();
  fetchMock
    .mockReturnValueOnce(jsonResponse(200, runBody({ status: "queued" })))
    .mockReturnValueOnce(jsonResponse(200, { id: "run_1", status: "cancelled" }))
    .mockReturnValueOnce(jsonResponse(200, runBody({ status: "cancelled" })));
  renderConsole();

  const kill = await screen.findByRole("button", { name: /kill run/i });
  expect(kill).toBeEnabled();
  await user.click(kill);

  await waitFor(() =>
    expect(fetchMock).toHaveBeenCalledWith(
      "/runs/run_1/cancel",
      expect.objectContaining({ method: "POST" }),
    ),
  );
  await waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent("cancelled"),
  );
  expect(screen.getByRole("button", { name: /kill run/i })).toBeDisabled();
});

test("a failed cancel raises the page alert", async () => {
  const user = userEvent.setup();
  fetchMock
    .mockReturnValueOnce(jsonResponse(200, runBody({ status: "queued" })))
    .mockReturnValueOnce(
      jsonResponse(409, { error: "conflict", detail: "run already ended" }),
    );
  renderConsole();

  await user.click(await screen.findByRole("button", { name: /kill run/i }));

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("conflict");
  expect(alert).toHaveTextContent("run already ended");
  expect(screen.getByRole("status")).toHaveTextContent("queued");
});

test("Pause and Steer call no API and no EventSource", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(jsonResponse(200, runBody({ status: "queued" })));
  renderConsole();

  await screen.findByRole("region", { name: /evidence timeline/i });
  expect(screen.getByRole("button", { name: /pause/i })).toBeDisabled();

  await user.click(screen.getByRole("button", { name: /steer/i }));
  const drawer = await screen.findByRole("dialog", { name: /steer/i });
  expect(within(drawer).getByRole("textbox")).toBeInTheDocument();
  expect(within(drawer).getByRole("button", { name: /send/i })).toBeDisabled();

  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(eventSourceMock).not.toHaveBeenCalled();
  for (const call of fetchMock.mock.calls) {
    expect(call[0]).not.toMatch(/\/events$/);
  }
});
