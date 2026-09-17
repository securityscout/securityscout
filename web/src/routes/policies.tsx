import { useMutation, useQuery } from "@tanstack/react-query";
import { createRoute } from "@tanstack/react-router";
import { useState } from "react";

import { ApiError, apiRequest } from "../api";
import { rootRoute } from "./__root";

const BLAST_RADII = ["safe", "intrusive", "destructive"] as const;

type BlastRadius = (typeof BLAST_RADII)[number];

type Policies = {
  scope: Record<string, unknown>;
  blast_radius: BlastRadius;
  budget: Record<string, unknown>;
  models: Record<string, unknown>;
  auto_publish: boolean;
};

type Alert = { error: string; detail: string };

const JSON_FIELDS = [
  { key: "scope", label: "Scope" },
  { key: "budget", label: "Budget" },
  { key: "models", label: "Models" },
] as const;

function asAlert(err: unknown): Alert {
  if (err instanceof ApiError) {
    return { error: err.error, detail: err.detail };
  }
  return { error: "unavailable", detail: "" };
}

function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function parseObject(source: string): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  return parsed as Record<string, unknown>;
}

function PoliciesForm({ loaded }: { loaded: Policies }) {
  const [text, setText] = useState({
    scope: pretty(loaded.scope),
    budget: pretty(loaded.budget),
    models: pretty(loaded.models),
  });
  const [blastRadius, setBlastRadius] = useState<BlastRadius>(
    loaded.blast_radius,
  );
  const [autoPublish, setAutoPublish] = useState(loaded.auto_publish);
  const [invalid, setInvalid] = useState<Alert | null>(null);

  const save = useMutation({
    mutationFn: (body: Policies) =>
      apiRequest<Policies>("/policies", { method: "PUT", body }),
  });

  function submit() {
    save.reset();
    const parsed = JSON_FIELDS.map((field) => parseObject(text[field.key]));
    const badIndex = parsed.findIndex((value) => value === null);
    if (badIndex !== -1) {
      setInvalid({
        error: "invalid_request",
        detail: `${JSON_FIELDS[badIndex].label} is not a JSON object`,
      });
      return;
    }
    setInvalid(null);
    const [scope, budget, models] = parsed as Record<string, unknown>[];
    save.mutate({
      scope,
      blast_radius: blastRadius,
      budget,
      models,
      auto_publish: autoPublish,
    });
  }

  const alert = invalid ?? (save.isError ? asAlert(save.error) : null);

  return (
    <>
      {alert ? (
        <p role="alert">
          {alert.error} {alert.detail}
        </p>
      ) : null}
      <form
        className="policy-form"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <fieldset className="form-section">
          <legend className="form-section-label">Execution</legend>
          <label>
            Blast radius
            <select
              value={blastRadius}
              onChange={(event) =>
                setBlastRadius(event.target.value as BlastRadius)
              }
            >
              {BLAST_RADII.map((radius) => (
                <option key={radius} value={radius}>
                  {radius}
                </option>
              ))}
            </select>
          </label>
        </fieldset>
        <fieldset className="form-section">
          <legend className="form-section-label">Automation</legend>
          <label>
            Auto-publish
            <input
              type="checkbox"
              checked={autoPublish}
              onChange={(event) => setAutoPublish(event.target.checked)}
            />
          </label>
        </fieldset>
        <fieldset className="form-section">
          <legend className="form-section-label">Configuration</legend>
          {JSON_FIELDS.map((field) => (
            <label key={field.key}>
              {field.label}
              <textarea
                value={text[field.key]}
                onChange={(event) =>
                  setText((old) => ({ ...old, [field.key]: event.target.value }))
                }
              />
            </label>
          ))}
        </fieldset>
        <button type="submit">Save</button>
      </form>
    </>
  );
}

export function PoliciesPage() {
  const { data, error, isError } = useQuery({
    queryKey: ["policies"],
    queryFn: () => apiRequest<Policies>("/policies"),
    staleTime: 0,
  });

  return (
    <>
      <header className="page-header">
        <h1 className="page-title">Policies</h1>
      </header>
      {isError ? (
        <p role="alert">
          {asAlert(error).error} {asAlert(error).detail}
        </p>
      ) : null}
      {data ? <PoliciesForm loaded={data} /> : null}
    </>
  );
}

export const policiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policies",
  component: PoliciesPage,
});
