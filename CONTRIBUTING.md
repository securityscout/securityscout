# Contributing

Thank you for helping with Security Scout. This document describes **commit messages** and **pre-merge checks**. For architecture and coding rules, see `CLAUDE.md` and `documentation/`.

## Commit messages (Conventional Commits)

We follow **[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)**: a small grammar for commit messages so history and tooling stay readable. The spec was inspired by the **[Angular](https://github.com/angular/angular)** team’s commit conventions; Angular still maintains an extended guide ([commit message guidelines](https://github.com/angular/angular/blob/main/contributing-docs/commit-message-guidelines.md)) that many teams use as a reference for types, scopes, and bodies.

### Format

```
<type>(<scope>): <short summary>

Optional body: explain *why*, reference issues/ADRs, note follow-ups.
Use a blank line between subject and body.

Optional footer: BREAKING CHANGE: … or Fixes #123
```

- **Subject line**: imperative mood (“Add…”, “Fix…”), not past tense. Keep the summary short (often ≤ 50–72 characters). No trailing period on the subject is common practice (see Angular’s guide).
- **Type** (common): `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `ci`, `build`.
- **Scope** (optional but encouraged): area of the codebase, e.g. `tools`, `webhooks`, `agents`, `config`, `worker`, `db`, `ci`, `deps`.
- **Breaking changes**: append `!` after the type or scope (e.g. `feat(api)!: …`) and/or a `BREAKING CHANGE:` paragraph in the footer, per the spec.

### Examples

```
feat(tools): add GitHub advisory fetch helper

docs(tools): tighten module docstrings

fix(webhooks): reject replayed payloads outside window

chore(ci): pin action digests for zizmor
```

Reference ADRs in the body when a change implements a recorded decision, e.g. _Implement semantic firewall behaviour (ADR-010)._

Roadmap **phases** (`documentation/build-plan.md`) can appear in the **scope** or **body** (e.g. “Phase 1 advisory slice”) instead of ad-hoc bracket prefixes in the subject.

### Why not ad-hoc tags?

Older notes sometimes used subjects like `[phase-1] …`. Prefer **`type(scope):`** so messages stay compatible with changelog tools and match the Conventional Commits ecosystem (used widely, e.g. in projects building on [semantic-release](https://github.com/semantic-release/semantic-release) and similar tooling).

## Before you open a PR

- Run **`make check`** (or the same steps CI runs: lint, typecheck, tests with coverage).
- Keep commits **atomic** when practical: one logical change per commit.
- Do not commit secrets; `.env` stays local (see `.env.example`).

## Further reading

| Resource                                                                                                                           | Role                                                                   |
| ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)                                                       | Normative commit grammar                                               |
| [Angular — commit message guidelines](https://github.com/angular/angular/blob/main/contributing-docs/commit-message-guidelines.md) | Detailed examples and team conventions (historical basis for the spec) |
| `CLAUDE.md`                                                                                                                        | Project-specific implementation standards                              |
