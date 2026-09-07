# Contributing

Security Scout is licensed under the [Apache License 2.0](LICENSE). By
submitting a pull request or patch, you agree that your contribution is
licensed under the same terms (Apache License 2.0, Section 5 — inbound
= outbound). No separate CLA is required.

## Branching until 1.0 ships

`v1.0` is the integration branch for this rewrite.

- Cut feature branches from `v1.0`.
- Open PRs **into `v1.0`**, not `main`.
- When the rewrite is ready to release, merge `v1.0` into `main` and tag.

After that release, feature PRs target `main`.

## Commit messages

[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
Imperative subject (`Add…`, `Fix…`), no trailing period. Common types:
`feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`.

```
feat(ingest): collapse duplicate scanner ids by content hash
```

## Before you open a PR

- `make test` must pass.
- Keep commits atomic: one logical change per commit.
- Do not commit secrets. `.env` stays local (see `.env.example`).
