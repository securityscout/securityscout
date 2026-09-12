import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./app";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("chain pane shows the hop out of f1 without a mount GET", () => {
  render(<App initialPath="/findings/f1" />);

  const chain = screen.getByRole("region", { name: /chain/i });
  expect(chain).toHaveTextContent("session");
  expect(chain).toHaveTextContent("f2");
  expect(within(chain).getByRole("listitem")).toHaveTextContent(
    /f1\s+session\s+→\s+f2/,
  );
  expect(within(chain).getByRole("link", { name: "f2" })).toHaveAttribute(
    "href",
    "/findings/f2",
  );
  expect(within(chain).queryByRole("link", { name: "f1" })).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(0);
});

test("chain pane shows the same hop, same direction, from f2", () => {
  render(<App initialPath="/findings/f2" />);

  const chain = screen.getByRole("region", { name: /chain/i });
  expect(chain).toHaveTextContent("session");
  expect(chain).toHaveTextContent("f1");
  expect(within(chain).getByRole("listitem")).toHaveTextContent(
    /f1\s+session\s+→\s+f2/,
  );
  expect(within(chain).getByRole("link", { name: "f1" })).toHaveAttribute(
    "href",
    "/findings/f1",
  );
  expect(within(chain).queryByRole("link", { name: "f2" })).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(0);
});
