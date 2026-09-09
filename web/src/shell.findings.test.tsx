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

test("live GET updates kernel fields and keeps fixture severity/class", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      findings: [
        {
          id: "f1",
          repo_url: "https://github.com/acme/app.git",
          sha: "deadbeefcafebabedeadbeefcafebabe",
          rule_id: "rule.z",
          file: "src/z.py",
          line: 9,
          status: "published",
          run_id: "run_1",
          source_kind: "sast_csv",
        },
        {
          id: "f2",
          repo_url: "https://github.com/acme/app.git",
          sha: "deadbeefcafebabedeadbeefcafebabe",
          rule_id: "rule.y",
          file: "src/b.py",
          line: 2,
          status: "done",
          run_id: "run_1",
          source_kind: "sast_csv",
        },
      ],
    }),
  );

  render(<App initialPath="/engagements/eng_1" />);

  const row = await screen.findByRole("row", { name: /published/ });
  expect(row).toHaveTextContent("src/z.py:9");
  expect(row).toHaveTextContent("rule.z");
  expect(row).toHaveTextContent("High");
  expect(row).toHaveTextContent("CWE-89");

  expect(fetchMock).toHaveBeenCalledWith(
    "/findings?engagement_id=eng_1",
    expect.objectContaining({ method: "GET" }),
  );
  const [url] = fetchMock.mock.calls[0] as [string];
  expect(url).toBe("/findings?engagement_id=eng_1");
});

test("empty 200 clears the fixture rows", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, { findings: [] }));

  render(<App initialPath="/engagements/eng_1" />);

  await vi.waitFor(() => {
    expect(screen.queryByRole("row", { name: /f1/ })).not.toBeInTheDocument();
  });
  expect(screen.queryByRole("row", { name: /f2/ })).not.toBeInTheDocument();
});

test("extra id with no fixture renders with empty severity/class", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, {
      findings: [
        {
          id: "f3",
          repo_url: "https://github.com/acme/app.git",
          sha: "deadbeefcafebabedeadbeefcafebabe",
          rule_id: "rule.new",
          file: "src/c.py",
          line: 4,
          status: "needs_review",
          run_id: "run_1",
          source_kind: "sast_csv",
        },
      ],
    }),
  );

  render(<App initialPath="/engagements/eng_1" />);

  const row = await screen.findByRole("row", { name: /f3/ });
  expect(row).toHaveTextContent("rule.new");
  expect(row).not.toHaveTextContent("High");
  expect(row).not.toHaveTextContent("Medium");
  expect(row).not.toHaveTextContent(/CWE/);
  expect(document.body).not.toHaveTextContent(/proof/i);
});

test("!ok keeps fixture rows and raises an alert", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(503, { error: "unavailable", detail: "db locked" }),
  );

  render(<App initialPath="/engagements/eng_1" />);

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("unavailable");
  expect(alert).toHaveTextContent("db locked");
  expect(screen.getByRole("row", { name: /f1/ })).toBeInTheDocument();
  expect(screen.getByRole("row", { name: /f2/ })).toBeInTheDocument();
});

test("thrown fetch keeps fixture rows and raises an alert", async () => {
  fetchMock.mockRejectedValueOnce(new TypeError("network down"));

  render(<App initialPath="/engagements/eng_1" />);

  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("unavailable");
  expect(screen.getByRole("row", { name: /f1/ })).toBeInTheDocument();
  expect(screen.getByRole("row", { name: /f2/ })).toBeInTheDocument();
});

test("Enter opens the selected row's case file", async () => {
  fetchMock.mockRejectedValueOnce(new TypeError("network down"));
  const user = userEvent.setup();

  render(<App initialPath="/engagements/eng_1" />);
  await screen.findByRole("alert");

  await user.keyboard("{Enter}");

  expect(
    await screen.findByRole("button", { name: /^replay$/i }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText("Source")).toHaveTextContent("src/a.py");
});
