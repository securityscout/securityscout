import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test } from "vitest";

import { App } from "./app";

test("j/k moves finding row selection", async () => {
  const user = userEvent.setup();
  render(<App initialPath="/engagements/eng_1" />);

  expect(screen.getByRole("row", { name: /f1/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  expect(screen.getByRole("row", { name: /f2/ })).toHaveAttribute(
    "aria-selected",
    "false",
  );

  await user.keyboard("j");
  expect(screen.getByRole("row", { name: /f2/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  expect(screen.getByRole("row", { name: /f1/ })).toHaveAttribute(
    "aria-selected",
    "false",
  );

  await user.keyboard("k");
  expect(screen.getByRole("row", { name: /f1/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
});
