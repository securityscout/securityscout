import { useQuery } from "@tanstack/react-query";
import { createRoute } from "@tanstack/react-router";

import { findingById } from "../fixtures";
import { rootRoute } from "./__root";

export function FindingPage() {
  const { findingId } = findingRoute.useParams();
  const { data: finding } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => findingById(findingId),
    initialData: () => findingById(findingId),
  });

  if (!finding) {
    return <p>Finding {findingId}</p>;
  }

  return (
    <div>
      <header role="banner" className="banner">
        <span>{finding.severity}</span>
        <span>{finding.vuln_class}</span>
        <span className="mono">{finding.sha}</span>
        <span>{finding.status}</span>
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
        <button type="button">Replay</button>
        <button type="button">Accept</button>
        <button type="button">Reject</button>
        <button type="button">Accept risk</button>
      </div>
    </div>
  );
}

export const findingRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/findings/$findingId",
  component: FindingPage,
});
