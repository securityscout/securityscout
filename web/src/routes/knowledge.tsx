import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createRoute, Link, useNavigate } from '@tanstack/react-router';
import { useRef, useState } from 'react';

import { ApiError, apiRequest } from '../api';
import { knowledge as fixtureData } from '../knowledge-data';
import { rootRoute } from './__root';

const KINDS = ['pdf', 'jira', 'github_issue', 'github_advisory'] as const;

type KnowledgeSource = {
  id: string;
  kind: string;
  title: string;
  uri?: string;
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

function mergeIndexed(
  old: Knowledge | undefined,
  incoming: KnowledgeSource[],
): Knowledge {
  const current = old?.sources ?? [];
  const kept = current.map(
    (source) => incoming.find((row) => row.id === source.id) ?? source,
  );
  const appended = incoming.filter(
    (row) => !current.some((source) => source.id === row.id),
  );
  return {
    halflife_days: old?.halflife_days ?? fixture.halflife_days,
    sources: [...kept, ...appended],
  };
}

function asApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, 'unavailable', '');
}

// The upload is JSON, not multipart: `apiRequest` is the one fetch helper
// and it stringifies its body.
function readBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('could not read file'));
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result as ArrayBuffer);
      let binary = '';
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
  const navigate = useNavigate();
  const { source: selectedId, page } = knowledgeRoute.useSearch();
  const [kind, setKind] = useState('all');
  const fileInput = useRef<HTMLInputElement>(null);
  const jqlInput = useRef<HTMLInputElement>(null);
  const githubInput = useRef<HTMLInputElement>(null);
  const orgInput = useRef<HTMLInputElement>(null);
  const repoInput = useRef<HTMLInputElement>(null);
  const openedAfterIndex = useRef<string | null>(null);

  const {
    data: knowledge,
    error,
    isError,
  } = useQuery({
    queryKey: ['knowledge'],
    queryFn: () => apiRequest<Knowledge>('/knowledge'),
    initialData: () => fixture,
    staleTime: 0,
  });

  const upload = useMutation({
    mutationFn: async (file: File) =>
      apiRequest<KnowledgeSource>('/knowledge/pdf', {
        method: 'POST',
        body: { filename: file.name, content_b64: await readBase64(file) },
      }),
    onSuccess: (added) => {
      queryClient.setQueryData<Knowledge>(['knowledge'], (old) => ({
        halflife_days: old?.halflife_days ?? fixture.halflife_days,
        sources: [...(old?.sources ?? []), added],
      }));
    },
  });

  const jira = useMutation({
    mutationFn: (jql: string) =>
      apiRequest<{ jql: string; sources: KnowledgeSource[] }>(
        '/knowledge/jira',
        {
          method: 'POST',
          body: { jql },
        },
      ),
    onSuccess: (added) => {
      const sourceId = added.sources.at(-1)?.id ?? null;
      openedAfterIndex.current = sourceId;
      queryClient.setQueryData<Knowledge>(['knowledge'], (old) =>
        mergeIndexed(old, added.sources),
      );
      if (sourceId) {
        setKind('all');
        navigate({ to: '/knowledge', search: { source: sourceId } });
      }
    },
  });

  const github = useMutation({
    mutationFn: (q: string) =>
      apiRequest<{ q: string; sources: KnowledgeSource[] }>(
        '/knowledge/github-issues',
        {
          method: 'POST',
          body: { q },
        },
      ),
    onSuccess: (added) => {
      const sourceId = added.sources.at(-1)?.id ?? null;
      openedAfterIndex.current = sourceId;
      queryClient.setQueryData<Knowledge>(['knowledge'], (old) =>
        mergeIndexed(old, added.sources),
      );
      if (sourceId) {
        setKind('all');
        navigate({ to: '/knowledge', search: { source: sourceId } });
      }
    },
  });

  const advisories = useMutation({
    mutationFn: (body: { org: string; repo?: string }) =>
      apiRequest<{
        org: string;
        repo: string | null;
        sources: KnowledgeSource[];
      }>('/knowledge/github-advisories', { method: 'POST', body }),
    onSuccess: (added) => {
      const sourceId = added.sources.at(-1)?.id ?? null;
      openedAfterIndex.current = sourceId;
      queryClient.setQueryData<Knowledge>(['knowledge'], (old) =>
        mergeIndexed(old, added.sources),
      );
      if (sourceId) {
        setKind('all');
        navigate({ to: '/knowledge', search: { source: sourceId } });
      }
    },
  });

  const sources = knowledge.sources.filter(
    (source) => kind === 'all' || source.kind === kind,
  );
  const opened =
    sources.find((source) => source.id === selectedId) ??
    sources.find((source) => source.id === openedAfterIndex.current) ??
    sources[0] ??
    null;
  const alerts = [
    isError ? asApiError(error) : null,
    upload.isError ? asApiError(upload.error) : null,
    jira.isError ? asApiError(jira.error) : null,
    github.isError ? asApiError(github.error) : null,
    advisories.isError ? asApiError(advisories.error) : null,
  ].filter((item): item is ApiError => item !== null);

  return (
    <>
      <header className='page-header'>
        <h1 className='page-title'>Knowledge</h1>
      </header>
      {alerts.map((item) => (
        <p key={`${item.error}:${item.detail}`} role='alert'>
          {item.error} {item.detail}
        </p>
      ))}
      <p className='page-meta'>
        Chunks decay with a {knowledge.halflife_days}-day halflife.
      </p>
      <div className='page-toolbar'>
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
          <input ref={fileInput} type='file' accept='application/pdf' />
        </label>
        <button type='submit'>Upload</button>
      </form>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const jql = jqlInput.current?.value.trim() ?? '';
          if (jql) {
            jira.mutate(jql);
          }
        }}
      >
        <label>
          JQL
          <input ref={jqlInput} />
        </label>
        <button type='submit' disabled={jira.isPending}>
          Index Jira
        </button>
      </form>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const q = githubInput.current?.value.trim() ?? '';
          if (q) {
            github.mutate(q);
          }
        }}
      >
        <label>
          GitHub issues
          <input ref={githubInput} />
        </label>
        <button type='submit' disabled={github.isPending}>
          Index GitHub issues
        </button>
      </form>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const org = orgInput.current?.value.trim() ?? '';
          const repo = repoInput.current?.value.trim() ?? '';
          if (!org) {
            return;
          }
          advisories.mutate(repo ? { org, repo } : { org });
        }}
      >
        <label>
          Connect GitHub org
          <input ref={orgInput} />
        </label>
        <label>
          Advisory repo
          <input ref={repoInput} />
        </label>
        <button type='submit' disabled={advisories.isPending}>
          Index advisories
        </button>
      </form>
      <label>
        Kind
        <select value={kind} onChange={(event) => setKind(event.target.value)}>
          <option value='all'>all</option>
          {KINDS.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
      </div>
      <div className='panes case-file'>
        <section aria-label='Sources'>
          <ul>
            {sources.map((source) => (
              <li key={source.id}>
                <Link
                  to='/knowledge'
                  search={{ source: source.id, page: source.page ?? undefined }}
                >
                  {source.title}
                </Link>
                <span className='mono'> {source.citation}</span>
              </li>
            ))}
          </ul>
          {sources.length === 0 ? <p>No sources of this kind yet.</p> : null}
        </section>
        <section aria-label='Cited page'>
          {opened ? (
            <>
              <h2>{opened.citation}</h2>
              <p className='mono'>
                {opened.kind === 'jira' ||
                opened.kind === 'github_issue' ||
                opened.kind === 'github_advisory'
                  ? opened.uri
                  : `page ${page ?? opened.page}`}
              </p>
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
  path: '/knowledge',
  component: KnowledgePage,
  validateSearch: (search: Record<string, unknown>): KnowledgeSearch => ({
    source: typeof search.source === 'string' ? search.source : undefined,
    page: Number.isFinite(Number(search.page))
      ? Number(search.page)
      : undefined,
  }),
});
