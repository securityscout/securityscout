import { useQuery } from "@tanstack/react-query";
import { createRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
  type Row as TableRow,
} from "@tanstack/react-table";
import { Fragment, useEffect, useMemo, useState } from "react";

import { ApiError, apiRequest } from "../api";
import { findingById, findingsForEngagement } from "../fixtures";
import { rootRoute } from "./__root";

type KernelFinding = {
  id: string;
  repo_url: string;
  sha: string;
  rule_id: string;
  file: string;
  line: number;
  status: string;
  run_id: string;
  source_kind: string;
};

type Row = KernelFinding & { severity: string; vuln_class: string };

function asApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, "unavailable", "");
}

function toRow(kernel: KernelFinding): Row {
  const fixture = findingById(kernel.id);
  return {
    ...kernel,
    severity: fixture?.severity ?? "",
    vuln_class: fixture?.vuln_class ?? "",
  };
}

async function fetchFindings(engId: string): Promise<Row[]> {
  const data = await apiRequest<{ findings: KernelFinding[] }>(
    `/findings?engagement_id=${encodeURIComponent(engId)}`,
  );
  return data.findings.map(toRow);
}

const columnHelper = createColumnHelper<Row>();

const columns = [
  columnHelper.accessor("id", { header: "ID" }),
  columnHelper.accessor("severity", { header: "Severity" }),
  columnHelper.accessor("vuln_class", { header: "Class" }),
  columnHelper.display({
    id: "location",
    header: "Location",
    cell: (info) => `${info.row.original.file}:${info.row.original.line}`,
  }),
  columnHelper.accessor("status", { header: "Status" }),
  columnHelper.accessor("rule_id", { header: "Rule" }),
];

const SEVERITY_TOKENS: Record<string, string> = {
  critical: "--color-sev-critical",
  high: "--color-sev-high",
  medium: "--color-sev-medium",
};

function severityToken(severity: string): string {
  return SEVERITY_TOKENS[severity.toLowerCase()] ?? "--color-sev-low";
}

type RuleGroup = { ruleId: string; rows: TableRow<Row>[] };

function groupByRule(rows: TableRow<Row>[]): RuleGroup[] {
  const groups: RuleGroup[] = [];
  for (const row of rows) {
    const group = groups.find((each) => each.ruleId === row.original.rule_id);
    if (group) {
      group.rows.push(row);
    } else {
      groups.push({ ruleId: row.original.rule_id, rows: [row] });
    }
  }
  return groups;
}

export function EngagementPage() {
  const { engId } = engagementRoute.useParams();
  const navigate = useNavigate();
  const {
    data: rows,
    error,
    isError,
  } = useQuery({
    queryKey: ["findings", engId],
    queryFn: () => fetchFindings(engId),
    initialData: () => findingsForEngagement(engId).map(toRow),
    staleTime: 0,
  });
  const [selectedId, setSelectedId] = useState(rows[0]?.id ?? "");
  if (rows.length > 0 && !rows.some((row) => row.id === selectedId)) {
    setSelectedId(rows[0].id);
  }

  const table = useReactTable({
    data: rows,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  const groups = useMemo(
    () => groupByRule(table.getRowModel().rows),
    [table, rows],
  );
  const orderedIds = useMemo(
    () => groups.flatMap((group) => group.rows.map((row) => row.original.id)),
    [groups],
  );
  const selected = rows.find((row) => row.id === selectedId);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }
      if (event.key !== "j" && event.key !== "k" && event.key !== "Enter") {
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
      if (event.key === "Enter") {
        if (selectedId) {
          navigate({
            to: "/findings/$findingId",
            params: { findingId: selectedId },
          });
        }
        return;
      }
      setSelectedId((current) => {
        const index = orderedIds.indexOf(current);
        const next =
          event.key === "j"
            ? Math.min(index + 1, orderedIds.length - 1)
            : Math.max(index - 1, 0);
        return orderedIds[next] ?? current;
      });
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [orderedIds, selectedId, navigate]);

  return (
    <>
      {isError ? (
        <p role="alert">
          {asApiError(error).error} {asApiError(error).detail}
        </p>
      ) : null}
      <h1 className="page-title">Findings</h1>
      <label className="group-toggle">
        <input type="checkbox" checked disabled />
        Group by rule
      </label>
      <div className="findings-pane">
        <table>
          <thead>
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((header) => (
                  <th key={header.id}>
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext(),
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {groups.map((group) => (
              <Fragment key={group.ruleId}>
                <tr className="group-head">
                  <th scope="colgroup" colSpan={columns.length}>
                    {group.ruleId}
                  </th>
                </tr>
                {group.rows.map((row) => (
                  <tr
                    key={row.id}
                    aria-selected={row.original.id === selectedId}
                    onClick={() => setSelectedId(row.original.id)}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td
                        key={cell.id}
                        style={
                          cell.column.id === "severity"
                            ? {
                                color: `var(${severityToken(row.original.severity)})`,
                              }
                            : undefined
                        }
                      >
                        {cell.column.id === "id" ? (
                          <Link
                            to="/findings/$findingId"
                            params={{ findingId: row.original.id }}
                          >
                            {row.original.id}
                          </Link>
                        ) : (
                          flexRender(
                            cell.column.columnDef.cell,
                            cell.getContext(),
                          )
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </Fragment>
            ))}
          </tbody>
        </table>
        <section className="detail-pane" aria-label="Detail">
          {selected ? (
            <>
              <p className="mono">
                {selected.file}:{selected.line}
              </p>
              <p>{selected.status}</p>
            </>
          ) : null}
        </section>
      </div>
    </>
  );
}

export const engagementRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/engagements/$engId",
  component: EngagementPage,
});
