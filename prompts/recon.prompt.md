# Recon Agent Prompt

> **Draft.** This template is the structural placeholder that
> `triage/recon.py` will populate when recon comes online. The final body
> is finalized once recon is wired up.

## Goal

Produce a single JSON document inventorying a target repo's attack surface.
The pipeline is **polyglot** — this recon must work for any language a SAST
scanner reports (Java/Kotlin, Python, Ruby, PHP, JavaScript/TypeScript, Go, C/C++,
Rust, Scala, C#, …) and any framework on top.

## Variables the orchestrator will substitute

- `{{REPO_SLUG}}` — short identifier (e.g. `payments-api`, `web-frontend`)
- `{{REPO_URL}}` — full clone URL
- `{{SHA}}` — pinned commit to recon
- `{{LOCAL_PATH}}` — checkout location under `repos/`

## Required output sections (JSON keys)

The prompt loads the `vuln-recon` skill (read-only, `--mode plan`) and asks
for a JSON inventory with at least:

- `languages` — auto-detected, with line counts and percentages
- `frameworks` — detected web/data/build frameworks WITH VERSIONS
  (Spring, Django, Rails, Express, Next.js, Laravel,
  Symfony, Gin, Echo, .NET, Flask, FastAPI, …)
- `package_manifests` — every dependency manifest found: `pom.xml`,
  `requirements*.txt`, `pyproject.toml`, `Pipfile`,
  `Gemfile`, `package.json`, `composer.json`,
  `go.mod`, `Cargo.toml`, `*.csproj`, `build.gradle*`,
  `mix.exs`, `pubspec.yaml`, `Package.swift`
- `route_table` — HTTP routes / GraphQL resolvers / gRPC services /
  CLI commands / queue consumers / scheduled jobs
- `sink_inventory` — by class: filesystem, exec, SQL, HTTP egress,
  template render, deserialization, redirect, auth,
  crypto, SSRF
- `trust_boundaries` — auth gates, tenancy checks, allow/deny lists,
  CSRF tokens, RBAC scopes
- `osv_scan` — raw `osv-scanner --format json --output - .` output
  for dependency CVEs
- `notes` — anything else worth flagging for the triage worker

## Constraints

- Read-only. Do not modify files in the target repo.
- Wall-time budget: ≤20 minutes. If you can't finish, split by service/module.
- Every claim must cite `file:line`. No reasoning from memory.
