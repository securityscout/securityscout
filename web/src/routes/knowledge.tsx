import { createRoute } from "@tanstack/react-router";

import { rootRoute } from "./__root";

export function KnowledgePage() {
  return <h1>Knowledge</h1>;
}

export const knowledgeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/knowledge",
  component: KnowledgePage,
});
