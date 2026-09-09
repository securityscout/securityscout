import { useQuery } from "@tanstack/react-query";
import { createRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { useEffect, useState } from "react";

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
        const index = rows.findIndex((row) => row.id === current);
        const next =
          event.key === "j"
            ? Math.min(index + 1, rows.length - 1)
            : Math.max(index - 1, 0);
        return rows[next]?.id ?? current;
      });
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [rows, selectedId, navigate]);

  return (
    <>
      {isError ? (
        <p role="alert">
          {asApiError(error).error} {asApiError(error).detail}
        </p>
      ) : null}
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
          {table.getRowModel().rows.map((row) => (
            <tr
              key={row.id}
              aria-selected={row.original.id === selectedId}
              onClick={() => setSelectedId(row.original.id)}
            >
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id}>
                  {cell.column.id === "id" ? (
                    <Link
                      to="/findings/$findingId"
                      params={{ findingId: row.original.id }}
                    >
                      {row.original.id}
                    </Link>
                  ) : (
                    flexRender(cell.column.columnDef.cell, cell.getContext())
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export const engagementRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/engagements/$engId",
  component: EngagementPage,
});
