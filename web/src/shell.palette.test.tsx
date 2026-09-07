import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test } from "vitest";

import { App } from "./app";

test("meta+k opens the command palette", async () => {
  const user = userEvent.setup();
  render(<App />);

  expect(screen.queryByRole("dialog", { name: /command/i })).toBeNull();

  await user.keyboard("{Meta>}k{/Meta}");
  expect(
    screen.getByRole("dialog", { name: /command/i }),
  ).toBeInTheDocument();
});
