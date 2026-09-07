import { createRoute } from "@tanstack/react-router";

import { rootRoute } from "./__root";

export function PoliciesPage() {
  return <h1>Policies</h1>;
}

export const policiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policies",
  component: PoliciesPage,
});
