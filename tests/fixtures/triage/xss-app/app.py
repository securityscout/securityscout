"""Synthetic fixture: escaped HTML (not XSS)."""

import html


def render_name(name: str) -> str:
    return f"<p>{html.escape(name)}</p>"
