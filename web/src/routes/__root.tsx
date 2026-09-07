import { createRootRoute, Link, Outlet } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

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

export function Shell() {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

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
          <button type="button">Kill switch</button>
        </div>
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
