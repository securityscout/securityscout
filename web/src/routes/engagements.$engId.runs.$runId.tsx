import { useQuery } from "@tanstack/react-query";
import { createRoute } from "@tanstack/react-router";

import { ApiError, apiRequest } from "../api";
import { run as runFixture } from "../fixtures";
import { rootRoute } from "./__root";

type Run = {
  id: string;
  engagement_id: string;
  status: string;
};

function asApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, "unavailable", "");
}

export function RunPage() {
  const { runId } = runRoute.useParams();
  const { data: run, error } = useQuery({
    queryKey: ["run", runId],
    queryFn: () => apiRequest<Run>(`/runs/${runId}`),
    initialData: runId === runFixture.id ? runFixture : undefined,
    staleTime: 0,
    refetchOnWindowFocus: true,
    refetchInterval: (query) =>
      query.state.data?.status === "running" ? 1000 : false,
  });
  const status = run?.status ?? "";

  return (
    <div>
      <h1>Run {runId}</h1>
      <p role="status" data-live={status === "running" ? "true" : undefined}>
        {status}
      </p>
      {error ? (
        <p role="alert">
          {asApiError(error).error} {asApiError(error).detail}
        </p>
      ) : null}
    </div>
  );
}

export const runRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/engagements/$engId/runs/$runId",
  component: RunPage,
});
