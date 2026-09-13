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

const livePdf = {
  id: "ks_live",
  kind: "pdf",
  title: "q3-2025-assessment.pdf",
  uri: "q3-2025-assessment.pdf",
  assessment_date: "2025-06-01",
  sha256: "a".repeat(64),
  citation: "q3-2025-assessment.pdf p.4",
  page: 4,
  page_text: "orders IDOR on /v1 reachable without a session",
};

const liveJira = {
  id: "ks_jira",
  kind: "jira",
  title: "IDOR on /v1",
  uri: "ACME-12",
  assessment_date: "2025-06-01",
  sha256: "b".repeat(64),
  citation: "IDOR on /v1 ACME-12",
  page: null,
  page_text: "orders IDOR on /v1",
};

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("JQL submit POSTs /knowledge/jira and lists the returned source", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(201, { jql: 'project = ACME AND text ~ "IDOR"', sources: [liveJira] }),
  );

  render(<App initialPath="/knowledge" />);
  await screen.findByRole("link", { name: "q3-2025-assessment.pdf" });

  await user.type(screen.getByLabelText(/jql/i), 'project = ACME AND text ~ "IDOR"');
  await user.click(screen.getByRole("button", { name: /index jira/i }));

  expect(await screen.findByRole("link", { name: "IDOR on /v1" })).toBeInTheDocument();
  expect(screen.getByRole("region", { name: /cited page/i })).toHaveTextContent("ACME-12");
  expect(fetchMock).toHaveBeenCalledTimes(2);
  const [path, init] = fetchMock.mock.calls[1];
  expect(path).toBe("/knowledge/jira");
  expect(init.method).toBe("POST");
  expect(JSON.parse(init.body as string)).toEqual({
    jql: 'project = ACME AND text ~ "IDOR"',
  });
});

test("empty JQL does not POST", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );

  render(<App initialPath="/knowledge" />);
  await screen.findByRole("link", { name: "q3-2025-assessment.pdf" });

  await user.click(screen.getByRole("button", { name: /index jira/i }));

  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(fetchMock.mock.calls[0][0]).toBe("/knowledge");
});

test("Jira index from a filtered PDF view opens the new issue", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(201, { jql: 'project = ACME AND text ~ "IDOR"', sources: [liveJira] }),
  );

  render(<App initialPath="/knowledge?source=ks_live" />);
  await screen.findByRole("link", { name: "q3-2025-assessment.pdf" });

  await user.selectOptions(screen.getByLabelText(/kind/i), "pdf");
  await user.type(screen.getByLabelText(/jql/i), 'project = ACME AND text ~ "IDOR"');
  await user.click(screen.getByRole("button", { name: /index jira/i }));

  expect(await screen.findByRole("link", { name: "IDOR on /v1" })).toBeInTheDocument();
  const cited = screen.getByRole("region", { name: /cited page/i });
  expect(cited).toHaveTextContent("ACME-12");
  expect(cited).not.toHaveTextContent("reachable without a session");
  expect(fetchMock).toHaveBeenCalledTimes(2);
  expect(fetchMock.mock.calls[0][0]).toBe("/knowledge");
  expect(fetchMock.mock.calls[1][0]).toBe("/knowledge/jira");
});

test("a failed Jira POST keeps the PDF fixture and raises alert", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(503, { error: "unavailable", detail: "db locked" }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(502, { error: "upstream", detail: "jira search failed" }),
  );

  render(<App initialPath="/knowledge" />);
  expect(
    await screen.findByRole("link", { name: "v1-idor-assessment.pdf" }),
  ).toBeInTheDocument();

  await user.type(screen.getByLabelText(/jql/i), "project = ACME");
  await user.click(screen.getByRole("button", { name: /index jira/i }));

  const alerts = await screen.findAllByRole("alert");
  expect(alerts.some((node) => node.textContent?.includes("upstream"))).toBe(true);
  expect(
    screen.getByRole("link", { name: "v1-idor-assessment.pdf" }),
  ).toBeInTheDocument();
});
