import { useMutation, useQuery } from "@tanstack/react-query";
import { createRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { ApiError, apiRequest } from "../api";
import { chainHops, findingById } from "../fixtures";
import { rootRoute } from "./__root";

type ReviewAction = "accept" | "reject" | "accept_risk";

type Ticket = {
  id: string;
  sink: string;
  external_id: string;
  url: string;
  published_at: string;
};

function asApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, "unavailable", "");
}

function ChainEnd({ findingId, endId }: { findingId: string; endId: string }) {
  if (endId === findingId) {
    return <span>{endId}</span>;
  }
  return (
    <Link to="/findings/$findingId" params={{ findingId: endId }}>
      {endId}
    </Link>
  );
}

export function FindingPage() {
  const { findingId } = findingRoute.useParams();
  const { data: finding } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => findingById(findingId),
    initialData: () => findingById(findingId),
  });
  const [reviewById, setReviewById] = useState<{
    id: string;
    status: string;
  } | null>(null);
  const [errorById, setErrorById] = useState<{
    id: string;
    error: ApiError;
  } | null>(null);
  const [replayById, setReplayById] = useState<{
    id: string;
    status: string;
  } | null>(null);
  const [ticketsById, setTicketsById] = useState<{
    id: string;
    tickets: Ticket[];
  } | null>(null);
  const status =
    reviewById !== null && reviewById.id === findingId
      ? reviewById.status
      : (finding?.status ?? "");
  const error =
    errorById !== null && errorById.id === findingId ? errorById.error : null;
  const replayStatus =
    replayById !== null && replayById.id === findingId
      ? replayById.status
      : null;
  const hops = chainHops.filter(
    (hop) => hop.from_id === findingId || hop.to_id === findingId,
  );
  const findingTickets =
    ticketsById !== null && ticketsById.id === findingId
      ? ticketsById.tickets
      : [];

  const review = useMutation({
    mutationFn: (action: ReviewAction) =>
      apiRequest<{ id: string; status: string; tickets?: Ticket[] }>(
        `/findings/${findingId}/review`,
        { method: "POST", body: { action } },
      ),
    onMutate: () => {
      setErrorById(null);
      setReplayById(null);
    },
    onSuccess: (data) => {
      setReviewById({ id: findingId, status: data.status });
      setTicketsById({ id: findingId, tickets: data.tickets ?? [] });
    },
    onError: (err: unknown) => {
      setErrorById({ id: findingId, error: asApiError(err) });
    },
  });

  const replay = useMutation({
    mutationFn: () =>
      apiRequest<{ finding_id: string; replay_status: string }>(
        `/findings/${findingId}/replay`,
        { method: "POST" },
      ),
    onMutate: () => {
      setErrorById(null);
      setReplayById(null);
    },
    onSuccess: (data) => {
      setReplayById({ id: findingId, status: data.replay_status });
    },
    onError: (err: unknown) => {
      setErrorById({ id: findingId, error: asApiError(err) });
    },
  });

  const replayMutate = replay.mutate;
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }
      if (event.key !== "r") {
        return;
      }
      if (document.querySelector('[role="dialog"]')) {
        return;
      }
      const target = event.target;
      if (
        target instanceof HTMLElement &&
        target.closest("input, textarea, select, [contenteditable='true']")
      ) {
        return;
      }
      event.preventDefault();
      replayMutate();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [replayMutate]);

  if (!finding) {
    return <p>Finding {findingId}</p>;
  }

  return (
    <div>
      <header role="banner" className="banner">
        <span>{finding.severity}</span>
        <span>{finding.vuln_class}</span>
        <span className="mono">{finding.sha}</span>
        <span>{status}</span>
      </header>
      <div className="panes">
        <section aria-label="Source">
          {finding.file}:{finding.line}
        </section>
        <section aria-label="Proof">{finding.proof.kind}</section>
        <section aria-label="Chain">
          <ol>
            {hops.map((hop) => (
              <li key={`${hop.from_id}-${hop.to_id}`}>
                <ChainEnd findingId={findingId} endId={hop.from_id} />
                <span className="mono"> {hop.kind} → </span>
                <ChainEnd findingId={findingId} endId={hop.to_id} />
              </li>
            ))}
          </ol>
        </section>
        <section aria-label="Knowledge" />
        <section aria-label="Ticket">
          {findingTickets.map((ticket) => (
            <a key={ticket.id} href={ticket.url}>
              {ticket.url}
            </a>
          ))}
        </section>
      </div>
      <div className="actions">
        <button type="button" onClick={() => replay.mutate()}>
          Replay
        </button>
        <button type="button" onClick={() => review.mutate("accept")}>
          Accept
        </button>
        <button type="button" onClick={() => review.mutate("reject")}>
          Reject
        </button>
        <button type="button" onClick={() => review.mutate("accept_risk")}>
          Accept risk
        </button>
      </div>
      {error ? (
        <p role="alert">
          {error.error} {error.detail}
        </p>
      ) : null}
      {replayStatus ? <p role="status">{replayStatus}</p> : null}
    </div>
  );
}

export const findingRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/findings/$findingId",
  component: FindingPage,
});
