export class ApiError extends Error {
  readonly status: number;
  readonly error: string;
  readonly detail: string;

  constructor(status: number, error: string, detail: string) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.error = error;
    this.detail = detail;
  }
}

function apiBase(): string {
  return (import.meta.env.VITE_API_BASE ?? "").replace(/\/$/, "");
}

function unavailable(status: number): ApiError {
  return new ApiError(status, "unavailable", "");
}

export async function apiRequest<T>(
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<T> {
  const headers: Record<string, string> = {};
  if (init.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  let response: Response;
  try {
    response = await fetch(`${apiBase()}${path}`, {
      method: init.method ?? "GET",
      headers,
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    });
  } catch {
    throw unavailable(0);
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw unavailable(response.status);
  }
  if (!response.ok) {
    const envelope = data as { error?: unknown; detail?: unknown };
    throw new ApiError(
      response.status,
      typeof envelope.error === "string" ? envelope.error : "unavailable",
      typeof envelope.detail === "string" ? envelope.detail : "",
    );
  }
  return data as T;
}
