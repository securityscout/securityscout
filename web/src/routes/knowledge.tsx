import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createRoute, Link } from "@tanstack/react-router";
import { useRef, useState } from "react";

import { ApiError, apiRequest } from "../api";
import { knowledge as fixtureData } from "../knowledge-data";
import { rootRoute } from "./__root";

const KINDS = ["pdf", "jira", "github_issue", "github_advisory"] as const;

type KnowledgeSource = {
  id: string;
  kind: string;
  title: string;
  assessment_date: string;
  citation: string;
  page: number | null;
  page_text: string;
};

type Knowledge = { halflife_days: number; sources: KnowledgeSource[] };

type KnowledgeSearch = { source?: string; page?: number };

const fixture: Knowledge = {
  halflife_days: fixtureData.halflife_days,
  sources: fixtureData.sources.map((source) => ({ ...source })),
};

function asApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, "unavailable", "");
}

// The upload is JSON, not multipart: `apiRequest` is the one fetch helper
// and it stringifies its body.
function readBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("could not read file"));
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result as ArrayBuffer);
      let binary = "";
      for (let index = 0; index < bytes.length; index += 1) {
        binary += String.fromCharCode(bytes[index]);
      }
      resolve(btoa(binary));
    };
    reader.readAsArrayBuffer(file);
  });
}

export function KnowledgePage() {
  const queryClient = useQueryClient();
  const { source: selectedId, page } = knowledgeRoute.useSearch();
  const [kind, setKind] = useState("all");
  const fileInput = useRef<HTMLInputElement>(null);

  const {
    data: knowledge,
    error,
    isError,
  } = useQuery({
    queryKey: ["knowledge"],
    queryFn: () => apiRequest<Knowledge>("/knowledge"),
    initialData: () => fixture,
    staleTime: 0,
  });

  const upload = useMutation({
    mutationFn: async (file: File) =>
      apiRequest<KnowledgeSource>("/knowledge/pdf", {
        method: "POST",
        body: { filename: file.name, content_b64: await readBase64(file) },
      }),
    onSuccess: (added) => {
      queryClient.setQueryData<Knowledge>(["knowledge"], (old) => ({
        halflife_days: old?.halflife_days ?? fixture.halflife_days,
        sources: [...(old?.sources ?? []), added],
      }));
    },
  });

  const sources = knowledge.sources.filter(
    (source) => kind === "all" || source.kind === kind,
  );
  const opened =
    sources.find((source) => source.id === selectedId) ?? sources[0] ?? null;
  const alert = isError
    ? asApiError(error)
    : upload.isError
      ? asApiError(upload.error)
      : null;

  return (
    <>
      <h1>Knowledge</h1>
      {alert ? (
        <p role="alert">
          {alert.error} {alert.detail}
        </p>
      ) : null}
      <p>Chunks decay with a {knowledge.halflife_days}-day halflife.</p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const file = fileInput.current?.files?.[0];
          if (file) {
            upload.mutate(file);
          }
        }}
      >
        <label>
          PDF
          <input ref={fileInput} type="file" accept="application/pdf" />
        </label>
        <button type="submit">Upload</button>
      </form>
      <label>
        Kind
        <select value={kind} onChange={(event) => setKind(event.target.value)}>
          <option value="all">all</option>
          {KINDS.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
      <div className="panes">
        <section aria-label="Sources">
          <ul>
            {sources.map((source) => (
              <li key={source.id}>
                <Link
                  to="/knowledge"
                  search={{ source: source.id, page: source.page ?? undefined }}
                >
                  {source.title}
                </Link>
                <span className="mono"> {source.citation}</span>
              </li>
            ))}
          </ul>
          {sources.length === 0 ? <p>No sources of this kind yet.</p> : null}
        </section>
        <section aria-label="Cited page">
          {opened ? (
            <>
              <h2>{opened.citation}</h2>
              <p className="mono">page {page ?? opened.page}</p>
              <p>{opened.page_text}</p>
            </>
          ) : null}
        </section>
      </div>
    </>
  );
}

export const knowledgeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/knowledge",
  component: KnowledgePage,
  validateSearch: (search: Record<string, unknown>): KnowledgeSearch => ({
    source: typeof search.source === "string" ? search.source : undefined,
    page: Number.isFinite(Number(search.page)) ? Number(search.page) : undefined,
  }),
});
