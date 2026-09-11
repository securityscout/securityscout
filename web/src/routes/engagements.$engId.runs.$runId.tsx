import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createRoute } from "@tanstack/react-router";
import { useState } from "react";

import { ApiError, apiRequest } from "../api";
import { run as runFixture } from "../fixtures";
import { rootRoute } from "./__root";

type Span = {
  id: string;
  agent: string | null;
  tool: string | null;
  args_hash: string | null;
  result_sha256: string | null;
  t: string | null;
};

type Run = {
  id: string;
  engagement_id: string;
  status: string;
  playbook?: string;
  mode?: string;
  budget_spent_usd?: number;
  budget_limit_usd?: number | null;
  spans?: Span[];
};

const TERMINAL = ["cancelled", "done", "error"];

function asApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, "unavailable", "");
}

function steps(status: string): string[] {
  return ["queued", "running", TERMINAL.includes(status) ? status : "done"];
}

function short(hash: string | null): string {
  return (hash ?? "").slice(0, 8);
}

function agentOf(span: Span): string {
  return span.agent ?? "unknown";
}

function agentCounts(spans: Span[]): { agent: string; count: number }[] {
  const counts: { agent: string; count: number }[] = [];
  for (const span of spans) {
    const agent = agentOf(span);
    const seen = counts.find((entry) => entry.agent === agent);
    if (seen) {
      seen.count += 1;
    } else {
      counts.push({ agent, count: 1 });
    }
  }
  return counts;
}

function handoffs(spans: Span[]): string[] {
  const edges: string[] = [];
  for (let i = 1; i < spans.length; i += 1) {
    const from = agentOf(spans[i - 1]);
    const to = agentOf(spans[i]);
    const edge = `${from} → ${to}`;
    if (from !== to && !edges.includes(edge)) {
      edges.push(edge);
    }
  }
  return edges;
}

export function RunPage() {
  const { runId } = runRoute.useParams();
  const queryClient = useQueryClient();
  const [killError, setKillError] = useState<ApiError | null>(null);
  const [steerOpen, setSteerOpen] = useState(false);
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
  const spans = run?.spans ?? [];
  const spent = run?.budget_spent_usd ?? 0;
  const limit = run?.budget_limit_usd ?? null;
  const edges = handoffs(spans);

  const kill = useMutation({
    mutationFn: () =>
      apiRequest<{ id: string; status: string }>(`/runs/${runId}/cancel`, {
        method: "POST",
      }),
    onMutate: () => setKillError(null),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["run", runId] }),
    onError: (err: unknown) => setKillError(asApiError(err)),
  });

  const shown = killError ?? (error ? asApiError(error) : null);

  return (
    <div>
      <h1>Run {runId}</h1>
      <div className="banner">
        <p role="status" data-live={status === "running" ? "true" : undefined}>
          {status}
        </p>
        <progress
          aria-label="Budget"
          value={limit === null ? undefined : spent}
          max={limit === null ? undefined : limit}
        />
        <span className="mono">{spent.toFixed(2)} USD spent</span>
      </div>

      <div className="console">
        <section aria-label="Playbook steps">
          <h2>Playbook</h2>
          <p className="mono">
            {run?.playbook ?? ""} {run?.mode ?? ""}
          </p>
          <ol>
            {steps(status).map((step) => (
              <li key={step} aria-current={step === status ? "step" : undefined}>
                {step}
              </li>
            ))}
          </ol>
        </section>

        <section aria-label="Evidence timeline">
          <h2>Evidence</h2>
          {spans.length === 0 ? (
            <p>No tool spans yet. The gateway writes one per call.</p>
          ) : (
            <ol>
              {spans.map((span) => (
                <li key={span.id}>
                  <time className="mono" dateTime={span.t ?? undefined}>
                    {span.t ?? ""}
                  </time>{" "}
                  {agentOf(span)}{" "}
                  {span.tool ?? "unknown"}{" "}
                  <code>
                    {short(span.args_hash)} → {short(span.result_sha256)}
                  </code>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section aria-label="Agent graph">
          <h2>Agent graph</h2>
          {spans.length === 0 ? (
            <p>No agents have run.</p>
          ) : (
            <>
              <ul aria-label="Agents">
                {agentCounts(spans).map((entry) => (
                  <li key={entry.agent}>
                    {entry.agent} ×{entry.count}
                  </li>
                ))}
              </ul>
              {edges.length === 0 ? (
                <p>One agent so far — no handoffs.</p>
              ) : (
                <ul aria-label="Handoffs">
                  {edges.map((edge) => (
                    <li key={edge}>{edge}</li>
                  ))}
                </ul>
              )}
            </>
          )}
        </section>
      </div>

      <div className="actions">
        <button
          type="button"
          onClick={() => kill.mutate()}
          disabled={TERMINAL.includes(status) || kill.isPending}
        >
          Kill run
        </button>
        <button type="button" disabled>
          Pause
        </button>
        <button type="button" onClick={() => setSteerOpen((open) => !open)}>
          Steer
        </button>
      </div>
      <p>No worker is attached. Pause and steer land with the hunt playbook.</p>

      {steerOpen ? (
        <div role="dialog" aria-label="Steer" className="drawer">
          <label>
            Instruction
            <textarea rows={3} />
          </label>
          <button type="button" disabled>
            Send
          </button>
          <button type="button" onClick={() => setSteerOpen(false)}>
            Close
          </button>
        </div>
      ) : null}

      {shown ? (
        <p role="alert">
          {shown.error} {shown.detail}
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
