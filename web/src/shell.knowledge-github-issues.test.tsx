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

const liveIssue = {
  id: "ks_gh",
  kind: "github_issue",
  title: "IDOR on /v1",
  uri: "acme/app#12",
  assessment_date: "2025-06-01",
  sha256: "c".repeat(64),
  citation: "IDOR on /v1 acme/app#12",
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

test("GitHub issues submit POSTs /knowledge/github-issues and lists the returned source", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(201, { q: "repo:acme/app IDOR", sources: [liveIssue] }),
  );

  render(<App initialPath="/knowledge" />);
  await screen.findByRole("link", { name: "q3-2025-assessment.pdf" });

  await user.type(screen.getByLabelText(/github issues/i), "repo:acme/app IDOR");
  await user.click(screen.getByRole("button", { name: /index github issues/i }));

  expect(await screen.findByRole("link", { name: "IDOR on /v1" })).toBeInTheDocument();
  expect(screen.getByRole("region", { name: /cited page/i })).toHaveTextContent(
    "acme/app#12",
  );
  expect(fetchMock).toHaveBeenCalledTimes(2);
  const [path, init] = fetchMock.mock.calls[1];
  expect(path).toBe("/knowledge/github-issues");
  expect(init.method).toBe("POST");
  expect(JSON.parse(init.body as string)).toEqual({ q: "repo:acme/app IDOR" });
});

test("empty GitHub issues submit does not POST", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );

  render(<App initialPath="/knowledge" />);
  await screen.findByRole("link", { name: "q3-2025-assessment.pdf" });

  await user.click(screen.getByRole("button", { name: /index github issues/i }));

  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(fetchMock.mock.calls[0][0]).toBe("/knowledge");
});

test("GitHub index from a filtered PDF view opens the new issue", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(201, { q: "repo:acme/app IDOR", sources: [liveIssue] }),
  );

  render(<App initialPath="/knowledge?source=ks_live" />);
  await screen.findByRole("link", { name: "q3-2025-assessment.pdf" });

  await user.selectOptions(screen.getByLabelText(/kind/i), "pdf");
  await user.type(screen.getByLabelText(/github issues/i), "repo:acme/app IDOR");
  await user.click(screen.getByRole("button", { name: /index github issues/i }));

  expect(await screen.findByRole("link", { name: "IDOR on /v1" })).toBeInTheDocument();
  const cited = screen.getByRole("region", { name: /cited page/i });
  expect(cited).toHaveTextContent("acme/app#12");
  expect(cited).not.toHaveTextContent("reachable without a session");
  expect(fetchMock).toHaveBeenCalledTimes(2);
  expect(fetchMock.mock.calls[0][0]).toBe("/knowledge");
  expect(fetchMock.mock.calls[1][0]).toBe("/knowledge/github-issues");
});

test("Index GitHub issues is disabled while the POST is pending", async () => {
  const user = userEvent.setup();
  let finishPost: (value: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    finishPost = resolve;
  });
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { sources: [livePdf], halflife_days: 365 }),
  );
  fetchMock.mockReturnValueOnce(pending);

  render(<App initialPath="/knowledge" />);
  await screen.findByRole("link", { name: "q3-2025-assessment.pdf" });

  await user.type(screen.getByLabelText(/github issues/i), "repo:acme/app IDOR");
  const button = screen.getByRole("button", { name: /index github issues/i });
  await user.click(button);

  expect(button).toBeDisabled();
  finishPost!(
    new Response(JSON.stringify({ q: "repo:acme/app IDOR", sources: [liveIssue] }), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    }),
  );
  expect(await screen.findByRole("link", { name: "IDOR on /v1" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /index github issues/i })).toBeEnabled();
});

test("a failed GitHub POST keeps the PDF fixture and raises alert", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(
    jsonResponse(503, { error: "unavailable", detail: "db locked" }),
  );
  fetchMock.mockReturnValueOnce(
    jsonResponse(502, { error: "upstream", detail: "github search failed" }),
  );

  render(<App initialPath="/knowledge" />);
  expect(
    await screen.findByRole("link", { name: "v1-idor-assessment.pdf" }),
  ).toBeInTheDocument();

  await user.type(screen.getByLabelText(/github issues/i), "repo:acme/app IDOR");
  await user.click(screen.getByRole("button", { name: /index github issues/i }));

  const alerts = await screen.findAllByRole("alert");
  expect(alerts.some((node) => node.textContent?.includes("upstream"))).toBe(true);
  expect(
    screen.getByRole("link", { name: "v1-idor-assessment.pdf" }),
  ).toBeInTheDocument();
});
