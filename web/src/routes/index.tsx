import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createRoute, Link } from "@tanstack/react-router";
import { useState } from "react";

import { ApiError, apiRequest } from "../api";
import { engagement } from "../fixtures";
import { rootRoute } from "./__root";

type EngagementRow = { id: string; name: string; org: string };

type EngagementResponse = EngagementRow & {
  policy_json: Record<string, unknown>;
  created_at: string;
};

type ImportResponse = EngagementResponse & { repos: unknown[] };

type FormError = { error: string; detail: string };

function asFormError(err: unknown): FormError {
  if (err instanceof ApiError) {
    return { error: err.error, detail: err.detail };
  }
  return { error: "unavailable", detail: "" };
}

const REPO_URL_RE =
  /^(?:https?:\/\/(?:www\.)?github\.com\/)?([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/;

function parseRepoUrl(input: string): { name: string; org: string } | null {
  const match = REPO_URL_RE.exec(input.trim());
  if (!match) {
    return null;
  }
  return { org: match[1], name: match[2] };
}

async function fetchEngagements(): Promise<EngagementRow[]> {
  const data = await apiRequest<{ engagements: EngagementRow[] }>("/engagements");
  return data.engagements;
}

export function EngagementsPage() {
  const queryClient = useQueryClient();
  const [invalidUrlError, setInvalidUrlError] = useState<FormError | null>(null);

  const {
    data: rows,
    error: listError,
    isError: isListError,
  } = useQuery({
    queryKey: ["engagements"],
    queryFn: fetchEngagements,
    initialData: [engagement],
    staleTime: 0,
  });

  function addRow(row: EngagementRow) {
    queryClient.setQueryData<EngagementRow[]>(["engagements"], (old) => [
      ...(old ?? []),
      row,
    ]);
  }

  const importMutation = useMutation({
    mutationFn: (org: string) =>
      apiRequest<ImportResponse>("/engagements/import", {
        method: "POST",
        body: { org },
      }),
    onSuccess: (body) => addRow({ id: body.id, name: body.name, org: body.org }),
  });

  const createMutation = useMutation({
    mutationFn: (body: {
      name: string;
      org: string;
      policy_json: Record<string, unknown>;
    }) => apiRequest<EngagementResponse>("/engagements", { method: "POST", body }),
    onSuccess: (body) => addRow({ id: body.id, name: body.name, org: body.org }),
  });

  const form = useForm({
    defaultValues: { org: "", repoUrl: "" },
    onSubmit: async ({ value, formApi }) => {
      importMutation.reset();
      createMutation.reset();
      const repoUrl = value.repoUrl.trim();
      const org = value.org.trim();
      if (repoUrl) {
        const parsed = parseRepoUrl(repoUrl);
        if (!parsed) {
          setInvalidUrlError({
            error: "invalid_url",
            detail: "enter a github.com repo URL or owner/name",
          });
          return;
        }
        setInvalidUrlError(null);
        try {
          await createMutation.mutateAsync({
            name: parsed.name,
            org: parsed.org,
            policy_json: {},
          });
          formApi.reset();
        } catch {
          // surfaced via createMutation.isError / .error
        }
        return;
      }
      if (org) {
        setInvalidUrlError(null);
        try {
          await importMutation.mutateAsync(org);
          formApi.reset();
        } catch {
          // surfaced via importMutation.isError / .error
        }
      }
    },
  });

  const alert = isListError
    ? asFormError(listError)
    : importMutation.isError
      ? asFormError(importMutation.error)
      : createMutation.isError
        ? asFormError(createMutation.error)
        : invalidUrlError;

  return (
    <>
      <h1 className="page-title">Engagements</h1>
      {alert ? (
        <p role="alert">
          {alert.error} {alert.detail}
        </p>
      ) : null}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          event.stopPropagation();
          void form.handleSubmit();
        }}
      >
        <form.Field name="org">
          {(field) => (
            <label>
              Org
              <input
                value={field.state.value}
                onChange={(event) => field.handleChange(event.target.value)}
              />
            </label>
          )}
        </form.Field>
        <form.Field name="repoUrl">
          {(field) => (
            <label>
              Repo URL
              <input
                value={field.state.value}
                onChange={(event) => field.handleChange(event.target.value)}
              />
            </label>
          )}
        </form.Field>
        <button type="submit">Add</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Org</th>
            <th>Env</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={4}>
                No GitHub token. Paste a fine-scoped PAT or run{" "}
                <code>gh auth login</code>.
              </td>
            </tr>
          ) : (
            rows.map((row) => (
              <tr key={row.id}>
                <td>
                  <Link to="/engagements/$engId" params={{ engId: row.id }}>
                    {row.id}
                  </Link>
                </td>
                <td>{row.name}</td>
                <td>{row.org}</td>
                <td></td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </>
  );
}

export const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: EngagementsPage,
});
