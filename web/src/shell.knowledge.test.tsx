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

const liveSource = {
  id: "ks_live",
  kind: "pdf",
  title: "q3-2025-assessment.pdf",
  uri: "q3-2025-assessment.pdf",
  assessment_date: "2025-09-01",
  sha256: "a".repeat(64),
  citation: "q3-2025-assessment.pdf p.4",
  page: 4,
  page_text: "orders IDOR on /v1 reachable without a session",
};

function liveList(): Promise<Response> {
  return jsonResponse(200, { sources: [liveSource], halflife_days: 365 });
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

test("live GET renders the source, its citation and the halflife", async () => {
  fetchMock.mockReturnValueOnce(liveList());

  render(<App initialPath="/knowledge" />);

  expect(
    await screen.findByRole("link", { name: "q3-2025-assessment.pdf" }),
  ).toBeInTheDocument();
  expect(screen.getByRole("region", { name: /cited page/i })).toHaveTextContent(
    "q3-2025-assessment.pdf p.4",
  );
  expect(screen.getByRole("region", { name: /cited page/i })).toHaveTextContent(
    "orders IDOR on /v1 reachable without a session",
  );
  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Knowledge");
  expect(document.body).toHaveTextContent("365");
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(fetchMock).toHaveBeenCalledWith(
    "/knowledge",
    expect.objectContaining({ method: "GET" }),
  );
});

test("?source=&page= opens that source's cited page", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      sources: [
        liveSource,
        {
          ...liveSource,
          id: "ks_other",
          title: "old.pdf",
          citation: "old.pdf p.9",
          page: 9,
          page_text: "session fixation on /login",
        },
      ],
      halflife_days: 365,
    }),
  );

  render(<App initialPath="/knowledge?source=ks_other&page=9" />);

  await screen.findByRole("link", { name: "old.pdf" });

  const pane = screen.getByRole("region", { name: /cited page/i });
  expect(pane).toHaveTextContent("old.pdf p.9");
  expect(pane).toHaveTextContent("session fixation on /login");
  expect(pane).not.toHaveTextContent("orders IDOR");
});

test("the fixture source stays on screen with a !ok list", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(503, { error: "unavailable", detail: "db locked" }),
  );

  render(<App initialPath="/knowledge" />);

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("unavailable");
  expect(alert).toHaveTextContent("db locked");
  expect(
    screen.getByRole("link", { name: "v1-idor-assessment.pdf" }),
  ).toBeInTheDocument();
  expect(screen.getByRole("region", { name: /cited page/i })).toHaveTextContent(
    "orders IDOR on /v1",
  );
});

test("upload POSTs the filename and base64 body, then lists the new source", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(liveList());
  fetchMock.mockReturnValueOnce(
    jsonResponse(201, {
      ...liveSource,
      id: "ks_new",
      title: "v1-idor-assessment.pdf",
      citation: "v1-idor-assessment.pdf p.1",
      page: 1,
      page_text: "orders IDOR on /v1",
    }),
  );

  render(<App initialPath="/knowledge" />);
  await screen.findByRole("link", { name: "q3-2025-assessment.pdf" });

  const file = new File(["%PDF-1.4 fixture"], "v1-idor-assessment.pdf", {
    type: "application/pdf",
  });
  await user.upload(screen.getByLabelText(/pdf/i), file);
  await user.click(screen.getByRole("button", { name: /upload/i }));

  expect(
    await screen.findByRole("link", { name: "v1-idor-assessment.pdf" }),
  ).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledTimes(2);
  const [path, init] = fetchMock.mock.calls[1];
  expect(path).toBe("/knowledge/pdf");
  expect(init.method).toBe("POST");
  const body = JSON.parse(init.body as string);
  expect(body.filename).toBe("v1-idor-assessment.pdf");
  expect(atob(body.content_b64)).toBe("%PDF-1.4 fixture");
});

test("the kind filter is client-side and issues no second GET", async () => {
  const user = userEvent.setup();
  fetchMock.mockReturnValueOnce(liveList());

  render(<App initialPath="/knowledge" />);
  await screen.findByRole("link", { name: "q3-2025-assessment.pdf" });

  await user.selectOptions(screen.getByLabelText(/kind/i), "pdf");
  expect(
    screen.getByRole("link", { name: "q3-2025-assessment.pdf" }),
  ).toBeInTheDocument();

  await user.selectOptions(screen.getByLabelText(/kind/i), "jira");
  expect(
    screen.queryByRole("link", { name: "q3-2025-assessment.pdf" }),
  ).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});
