import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createBrowserHistory,
  createMemoryHistory,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import { useState } from "react";

import { rootRoute } from "./routes/__root";
import { calibrationRoute } from "./routes/calibration";
import { engagementRoute } from "./routes/engagements.$engId";
import { runRoute } from "./routes/engagements.$engId.runs.$runId";
import { findingRoute } from "./routes/findings.$findingId";
import { graphRoute } from "./routes/graph.$engId";
import { indexRoute } from "./routes/index";
import { knowledgeRoute } from "./routes/knowledge";
import { policiesRoute } from "./routes/policies";

const routeTree = rootRoute.addChildren([
  indexRoute,
  engagementRoute,
  runRoute,
  findingRoute,
  graphRoute,
  knowledgeRoute,
  policiesRoute,
  calibrationRoute,
]);

function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        refetchOnWindowFocus: false,
        staleTime: Infinity,
      },
    },
  });
}

function historyFor(initialPath?: string) {
  if (initialPath !== undefined) {
    return createMemoryHistory({ initialEntries: [initialPath] });
  }
  return createBrowserHistory();
}

function createAppRouter(initialPath?: string) {
  const router = createRouter({
    routeTree,
    history: historyFor(initialPath),
    scrollRestoration: false,
    defaultPendingMs: 0,
    defaultPendingMinMs: 0,
  });
  const stores = router.stores;
  // Tests query the first paint. Seed the match store so RouterProvider
  // does not wait on the client load transaction.
  if (!stores.setMatches || !stores.resolvedLocation || !stores.status) {
    throw new Error(
      "TanStack Router match store API changed; first-paint seed is broken",
    );
  }
  stores.setMatches(router.matchRoutes(router.latestLocation));
  stores.resolvedLocation.set(router.latestLocation);
  stores.status.set("idle");
  return router;
}

export function App({ initialPath }: { initialPath?: string } = {}) {
  const [queryClient] = useState(createQueryClient);
  const [router] = useState(() => createAppRouter(initialPath));

  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}
