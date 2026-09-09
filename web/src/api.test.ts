import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { ApiError, apiRequest } from "./api";

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
  vi.unstubAllGlobals();
});

test("GET returns parsed JSON", async () => {
  fetchMock.mockReturnValueOnce(jsonResponse(200, { findings: [] }));

  await expect(apiRequest("/findings")).resolves.toEqual({ findings: [] });
  expect(fetchMock).toHaveBeenCalledWith(
    "/findings",
    expect.objectContaining({ method: "GET", body: undefined }),
  );
});

test("review POST sends action body", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(200, { id: "f1", status: "published" }),
  );

  await expect(
    apiRequest("/findings/f1/review", {
      method: "POST",
      body: { action: "accept" },
    }),
  ).resolves.toEqual({ id: "f1", status: "published" });

  expect(fetchMock).toHaveBeenCalledWith(
    "/findings/f1/review",
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ action: "accept" }),
      headers: expect.objectContaining({
        "Content-Type": "application/json",
      }),
    }),
  );
});

test("replay 202 is queued and has no passed", async () => {
  const body = { finding_id: "f1", replay_status: "queued" };
  fetchMock.mockReturnValueOnce(jsonResponse(202, body));

  const result = await apiRequest<Record<string, unknown>>(
    "/findings/f1/replay",
    { method: "POST" },
  );

  expect(result).toEqual(body);
  expect(result).not.toHaveProperty("passed");
  expect(JSON.stringify(result)).not.toMatch(/passed/i);
  expect(fetchMock).toHaveBeenCalledWith(
    "/findings/f1/replay",
    expect.objectContaining({ method: "POST", body: undefined }),
  );
});

test("!ok throws ApiError from the envelope", async () => {
  fetchMock.mockReturnValueOnce(
    jsonResponse(409, {
      error: "illegal_transition",
      detail: "cannot transition from done to published",
    }),
  );

  const err = await apiRequest("/findings/f2/review", {
    method: "POST",
    body: { action: "accept" },
  }).catch((caught: unknown) => caught);

  expect(err).toBeInstanceOf(ApiError);
  expect(err).toMatchObject({
    status: 409,
    error: "illegal_transition",
    detail: "cannot transition from done to published",
  });
});

test("non-JSON error body throws ApiError unavailable", async () => {
  fetchMock.mockReturnValueOnce(
    Promise.resolve(new Response("bad gateway", { status: 502 })),
  );

  const err = await apiRequest("/findings").catch((caught: unknown) => caught);

  expect(err).toBeInstanceOf(ApiError);
  expect(err).toMatchObject({
    status: 502,
    error: "unavailable",
    detail: "",
  });
});

test("network failure throws ApiError unavailable", async () => {
  fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));

  const err = await apiRequest("/findings").catch((caught: unknown) => caught);

  expect(err).toBeInstanceOf(ApiError);
  expect(err).toMatchObject({
    status: 0,
    error: "unavailable",
    detail: "",
  });
});
