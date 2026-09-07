import { createRoute } from "@tanstack/react-router";

import { rootRoute } from "./__root";

export function CalibrationPage() {
  return <h1>Calibration</h1>;
}

export const calibrationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/calibration",
  component: CalibrationPage,
});
