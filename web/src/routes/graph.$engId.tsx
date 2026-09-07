import { createRoute } from "@tanstack/react-router";

import { rootRoute } from "./__root";

export function GraphPage() {
  const { engId } = graphRoute.useParams();
  return <h1>Graph {engId}</h1>;
}

export const graphRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/graph/$engId",
  component: GraphPage,
});
