import { createRoute } from "@tanstack/react-router";

import { rootRoute } from "./__root";

export function RunPage() {
  const { runId } = runRoute.useParams();
  return <h1>Run {runId}</h1>;
}

export const runRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/engagements/$engId/runs/$runId",
  component: RunPage,
});
