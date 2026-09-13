import { useQuery } from "@tanstack/react-query";
import { createRoute, Link } from "@tanstack/react-router";

import { ApiError, apiRequest } from "../api";
import { chainHops, findingsForEngagement } from "../fixtures";
import { rootRoute } from "./__root";

type GraphNode = { id: string; kind: string; label: string };

type GraphHop = {
  id: string;
  from_id: string;
  to_id: string;
  kind: string;
  evidence_uri: string;
};

type Graph = { engagement_id: string; nodes: GraphNode[]; hops: GraphHop[] };

function asApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, "unavailable", "");
}

function fixtureGraph(engId: string): Graph {
  const nodes = findingsForEngagement(engId).map((finding) => ({
    id: finding.id,
    kind: "finding",
    label: `${finding.file}:${finding.line}`,
  }));
  const known = new Set(nodes.map((node) => node.id));
  const hops = chainHops
    .filter((hop) => known.has(hop.from_id) && known.has(hop.to_id))
    .map((hop) => ({
      id: `${hop.from_id}-${hop.to_id}`,
      from_id: hop.from_id,
      to_id: hop.to_id,
      kind: hop.kind,
      evidence_uri: "",
    }));
  const endpoints = new Set(hops.flatMap((hop) => [hop.from_id, hop.to_id]));
  return {
    engagement_id: engId,
    nodes: nodes.filter((node) => endpoints.has(node.id)),
    hops,
  };
}

export function GraphPage() {
  const { engId } = graphRoute.useParams();
  const {
    data: graph,
    error,
    isError,
  } = useQuery({
    queryKey: ["graph", engId],
    queryFn: () => apiRequest<Graph>(`/engagements/${engId}/graph`),
    initialData: () => fixtureGraph(engId),
    staleTime: 0,
  });
  const labels = new Map(graph.nodes.map((node) => [node.id, node.label]));

  return (
    <>
      <h1>Graph {engId}</h1>
      {isError ? (
        <p role="alert">
          {asApiError(error).error} {asApiError(error).detail}
        </p>
      ) : null}
      <div className="panes">
        <section aria-label="Attack graph">
          {/* role kept explicit: list-style: none drops it in Safari/VO */}
          <ul role="list" aria-label="Nodes" className="mono node-list">
            {graph.nodes.map((node) => (
              <li key={node.id}>{node.label}</li>
            ))}
          </ul>
          {graph.hops.length === 0 ? (
            <p>
              No chain hops yet. A hunt records one when it reaches a finding
              from another.
            </p>
          ) : null}
          <ol>
            {graph.hops.map((hop) => (
              <li key={hop.id}>
                <Link
                  to="/findings/$findingId"
                  params={{ findingId: hop.from_id }}
                >
                  {labels.get(hop.from_id) ?? hop.from_id}
                </Link>
                <span className="mono"> {hop.kind} → </span>
                <Link to="/findings/$findingId" params={{ findingId: hop.to_id }}>
                  {labels.get(hop.to_id) ?? hop.to_id}
                </Link>
              </li>
            ))}
          </ol>
        </section>
      </div>
    </>
  );
}

export const graphRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/graph/$engId",
  component: GraphPage,
});
