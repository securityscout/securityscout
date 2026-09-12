import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { App } from "./app";
import { calibration } from "./calibration-data";

test("/calibration shows both seed labels, pass_k, and cost_usd", () => {
  render(<App initialPath="/calibration" />);

  const region = screen.getByRole("region", { name: /calibration/i });
  expect(region).toHaveTextContent("true_positive");
  expect(region).toHaveTextContent("false_positive");
  expect(region).toHaveTextContent(new RegExp(`pass_k.*${calibration.pass_k}`, "is"));
  expect(region).toHaveTextContent(new RegExp(`cost_usd.*${calibration.cost_usd}`, "is"));
});
