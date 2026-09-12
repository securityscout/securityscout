import { createRootRoute, Link, Outlet } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { ApiError, apiRequest } from "../api";

const NAV = [
  { label: "Engagements", to: "/" },
  { label: "Runs", to: "/engagements/$engId/runs/$runId", params: { engId: "eng_1", runId: "run_1" } },
  { label: "Findings", to: "/findings/$findingId", params: { findingId: "f1" } },
  { label: "Graph", to: "/graph/$engId", params: { engId: "eng_1" } },
  { label: "Knowledge", to: "/knowledge" },
  { label: "Policies", to: "/policies" },
  { label: "Calibration", to: "/calibration" },
] as const;

function dialogItems(dialog: HTMLElement | null) {
  return dialog ? [...dialog.querySelectorAll<HTMLElement>("a, button")] : [];
}

function asApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, "unavailable", "");
}

async function killAllRuns(): Promise<ApiError[]> {
  const { engagements } = await apiRequest<{ engagements: { id: string }[] }>(
    "/engagements",
  );
  const failures: ApiError[] = [];
  for (const eng of engagements) {
    const { runs } = await apiRequest<{ runs: { id: string; status: string }[] }>(
      `/engagements/${eng.id}/runs`,
    );
    for (const run of runs) {
      if (run.status !== "queued" && run.status !== "running") {
        continue;
      }
      try {
        await apiRequest(`/runs/${run.id}/cancel`, { method: "POST" });
      } catch (err) {
        failures.push(asApiError(err));
      }
    }
  }
  return failures;
}

export function Shell() {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [killErrors, setKillErrors] = useState<ApiError[]>([]);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  async function handleKill() {
    setKillErrors([]);
    try {
      setKillErrors(await killAllRuns());
    } catch (err) {
      setKillErrors([asApiError(err)]);
    }
  }

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setPaletteOpen(true);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (!paletteOpen) {
      return;
    }
    const dialog = dialogRef.current;
    const trigger = triggerRef.current;
    const restore =
      document.activeElement instanceof HTMLElement &&
      document.activeElement !== document.body
        ? document.activeElement
        : trigger;
    dialogItems(dialog)[0]?.focus();

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        setPaletteOpen(false);
        return;
      }
      if (event.key !== "Tab") {
        return;
      }
      const items = dialogItems(dialog);
      if (items.length === 0) {
        event.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      restore?.focus();
    };
  }, [paletteOpen]);

  return (
    <div className="shell">
      <nav className="rail" aria-label="Rail" inert={paletteOpen || undefined}>
        {NAV.map((item) => (
          <Link key={item.label} to={item.to} params={"params" in item ? item.params : undefined}>
            {item.label}
          </Link>
        ))}
      </nav>
      <div className="main" inert={paletteOpen || undefined}>
        <div className="top">
          <button
            ref={triggerRef}
            type="button"
            onClick={() => setPaletteOpen(true)}
          >
            Command palette
          </button>
          <span>Budget remaining</span>
          <button type="button" onClick={() => void handleKill()}>
            Kill switch
          </button>
        </div>
        {killErrors.length > 0 ? (
          <p role="alert">
            {killErrors.map((err) => `${err.error} ${err.detail}`).join("; ")}
          </p>
        ) : null}
        <div className="page">
          <Outlet />
        </div>
      </div>
      {paletteOpen ? (
        <div
          ref={dialogRef}
          role="dialog"
          aria-label="Command palette"
          aria-modal="true"
          className="palette"
        >
          {NAV.map((item) => (
            <Link
              key={item.label}
              to={item.to}
              params={"params" in item ? item.params : undefined}
              onClick={() => setPaletteOpen(false)}
            >
              {item.label}
            </Link>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export const rootRoute = createRootRoute({
  component: Shell,
});
