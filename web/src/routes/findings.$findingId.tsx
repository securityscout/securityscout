import { useMutation, useQuery } from "@tanstack/react-query";
import { createRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { ApiError, apiRequest } from "../api";
import { findingById } from "../fixtures";
import { rootRoute } from "./__root";

type ReviewAction = "accept" | "reject" | "accept_risk";

function asApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, "unavailable", "");
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

  const review = useMutation({
    mutationFn: (action: ReviewAction) =>
      apiRequest<{ id: string; status: string }>(
        `/findings/${findingId}/review`,
        { method: "POST", body: { action } },
      ),
    onMutate: () => {
      setErrorById(null);
      setReplayById(null);
    },
    onSuccess: (data) => {
      setReviewById({ id: findingId, status: data.status });
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
        <section aria-label="Chain" />
        <section aria-label="Knowledge" />
        <section aria-label="Ticket" />
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
