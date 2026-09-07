import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { App } from "./app";

test("fixture finding case-file layout", () => {
  render(<App initialPath="/findings/f1" />);

  const header = screen.getByRole("banner");
  expect(header).toHaveTextContent("High");
  expect(header).toHaveTextContent("CWE-89");
  expect(header).toHaveTextContent("deadbeefcafebabedeadbeefcafebabe");
  expect(header).toHaveTextContent("needs_review");

  expect(screen.getByRole("region", { name: /source/i })).toHaveTextContent(
    "src/a.py:1",
  );
  expect(screen.getByRole("region", { name: /proof/i })).toBeInTheDocument();
  expect(screen.getByRole("region", { name: /chain/i })).toBeInTheDocument();
  expect(
    screen.getByRole("region", { name: /knowledge/i }),
  ).toBeInTheDocument();
  expect(screen.getByRole("region", { name: /ticket/i })).toBeInTheDocument();

  expect(screen.getByRole("button", { name: /^replay$/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /^accept$/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /^reject$/i })).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: /accept.risk/i }),
  ).toBeInTheDocument();
});
