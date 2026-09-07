# Security Scout

LLM-assisted batch triage pipeline for SAST findings. This tree is the
**v1.0 rewrite** of [securityscout](https://github.com/securityscout/securityscout).
Feature work lands on `v1.0` until that branch is ready to merge to
`main` and release.

This is **the implementer's repo** — not a place to commit changes to
target repos. All target repos are accessed read-only.

## Status

| Surface          | State                                                |
| ---------------- | ---------------------------------------------------- |
| Bootstrap        | done (`make bootstrap` + `make verify`)              |
| Schema + DB      | done (`triage/db.py`, `make schema`)                 |
| Skill (vendored) | done (`data/sast-triage.SKILL.md`, `make skill`)     |
| Verdict contract | done (`data/verdict.schema.json` + tests)            |
| CSV ingest       | done (`triage/ingest.py`, `make ingest CSV=…`)       |
| Recon            | not yet implemented (`triage/recon.py` stub)         |
| Triage worker    | not yet implemented (`triage/triage_worker.py` stub) |
| Verifier         | not yet implemented (`triage/verifier.py` stub)      |
| Report           | not yet implemented (`triage/report.py` stub)        |
| Tickets          | not yet implemented (GitHub Issues + Jira)           |
| Calibration      | not yet implemented (`triage/calibrate.py` stub)     |

## Language and framework coverage

The pipeline is **language- and framework-agnostic by design**. The
orchestrator, SQLite schema, verdict contract, and consolidation logic make
zero assumptions about the target's language. The skill loaded by the agent
(`sast-triage`) carries per-class bypass checklists for every common vuln
class (path traversal, SSRF, SQLi, XSS, deserialization, IDOR, race
conditions, etc.) across the languages SAST scanners report — including
but not limited to:

| Language          | PoC runtime examples                                        |
| ----------------- | ----------------------------------------------------------- |
| Java / Kotlin     | Maven `mvn -q test` harness (preferred) or `jbang`          |
| Python            | `pytest` with source-copies or `sys.path` shim              |
| Node / TypeScript | `npm test` / `jest` / `mocha`; live `localhost` for Express |
| Ruby (Rails, etc) | `bundle exec rspec` / `minitest`                            |
| PHP               | `phpunit` / `composer test`                                 |
| Go                | `go test ./...`                                             |
| C / C++ / Rust    | `cmake --build && ctest` / `cargo test`                     |
| Anything HTTP     | minimal `curl` with captured request + response inline      |

If a SAST scanner flags it, this pipeline can triage it. The triage worker picks
the appropriate harness automatically based on the recon JSON's detected
languages/frameworks.

## Layout

```
securityscout/
├── pyproject.toml          # jsonschema + python-dotenv (Python 3.10+)
├── Makefile                # bootstrap | schema | verify | ingest | …
├── .env.example            # copy to .env and fill in
├── triage/                 # orchestrator code
│   ├── db.py               # SQLite schema + connection helpers
│   ├── config.py           # env loading, model slugs, budget guardrails
│   ├── verify.py           # bootstrap acceptance gate
│   ├── ingest.py           # SAST CSV → SQLite
│   └── …                   # recon | triage_worker | verifier | report | calibrate
├── prompts/                # recon + argue_tp + argue_fp prompt templates
├── data/
│   ├── verdict.schema.json     # JSON Schema 2020-12 for the verdict format
│   ├── finding-row.schema.json # validation schema for one ingested row
│   ├── sast-triage.SKILL.md    # vendored, polyglot-expanded skill
│   ├── known-tp.jsonl          # calibration TPs (seeded later)
│   └── known-fp.jsonl          # calibration FPs (seeded later)
├── repos/                  # gitignored — cloned target repos
├── .cache/                 # gitignored — per-(repo,SHA) recon JSON
├── verdicts/               # gitignored — per-finding verdict JSONs
├── poc/                    # gitignored — generated per-TP PoC scaffolds
└── findings/               # gitignored — generated per-TP markdown writeups
```

The companion skill is **vendored in this repo** at
`data/sast-triage.SKILL.md` (the polyglot-expanded copy — Step 4 covers
Java/Kotlin, Python, Node/TS, Ruby, PHP, Go, C/C++, Rust, C#/.NET, Scala,
and HTTP-shaped targets). `make skill` copies it into
`~/.cursor/skills/sast-triage/SKILL.md` where `cursor-agent` discovers
it. We deliberately do **not** pull from any upstream skill source so this
tool stays language-agnostic regardless of how that skill evolves.

## Quick start

```bash
# 1. Toolchain — Python deps, vendored skill, GitHub CLI if missing.
make bootstrap

# 2. SQLite schema
make schema

# 3. Verify everything is in place. Exit 0 = ready to ingest.
make verify

# 4. Ingest a SAST findings CSV. Drop the export at
#    data/csv/<file>.csv (gitignored), then:
make ingest CSV=data/csv/<file>.csv DRY=1
make ingest CSV=data/csv/<file>.csv
```

## CSV ingest

Source of truth for per-finding metadata is a generic SAST CSV. Each row
needs enough to anchor a triage:

- `scanner_finding_id` — the scanner's own id
- `sha` + `file` [+ `line`], **or** `line_of_code_url` parsed via
  host-specific regex. GitLab `/-/blob/<sha>/<path>#L<n>`, GitHub
  `/blob/<sha>/<path>#L<n>`, and Bitbucket `/src/<sha>/<path>#lines-<n>`
  are all supported.
- `rule_id` — drives the bypass-checklist selection in the skill
- `repo_url`, optional `branch`, `severity`, `confidence`, `category`,
  `scanner_name`, `scanner_url`, `description`
- Every other CSV column → `scanner_meta_json` for forward-compat

Synthetic primary key is `id = sha256(repo_url|sha|file|line|rule_id)`.
Re-ingest is idempotent and content-based: if a scanner reports the same
finding under two different ids, we collapse to one orchestrator row.

Default exclusion globs are **env-driven** so deployment-specific repo
names stay out of tracked code. Set `TRIAGE_DEFAULT_EXCLUDE_REPOS` in
`.env` to a comma-separated list of fnmatch globs — typically deliberately
vulnerable test-fixture / playground corpora that would burn budget on
synthetic findings. Matched rows land in the DB with `status='excluded'`
and the worker pool skips them.

```
# in .env
TRIAGE_DEFAULT_EXCLUDE_REPOS=*team-foo/test-fixtures*,*team-bar/sast-playground*
```

CLI `EXCLUDE=…` augments the env-driven defaults; `NO_DEFAULT_EXCLUDES=1`
opts out of them entirely.

CLI flags (`python -m triage.ingest --help`):

| Flag                           | Effect                                           |
| ------------------------------ | ------------------------------------------------ |
| `--csv PATH`                   | required — path to the SAST CSV                  |
| `--dry-run`                    | parse + validate + summarize, do not write       |
| `--exclude-repos GLOB[,GLOB…]` | extra fnmatch patterns to mark `status=excluded` |
| `--no-default-excludes`        | disable the built-in synthetic-corpus list       |
| `--db PATH`                    | override the SQLite DB path                      |

Each invocation appends one row to `ingest_runs` with `source_sha256`,
counts, and the path to any rejection log at
`data/ingest-rejects/<csv-stem>-rejects.jsonl`.

## Environment

Copy `.env.example` to `.env` and fill in:

- `TRIAGE_MODEL_PASS1` / `TRIAGE_MODEL_PASS2` — Opus-class model slugs
  from `cursor-agent models`. Defaults wired in `.env.example` use 4.7 +
  4.6 to ensure pass 1 and pass 2 are genuinely different models.
- `BUDGET_USD` — monthly aggregate cap. Defaults to 200.
- `PER_FINDING_USD_CEILING` — per-finding cap. Intentionally equal to the
  monthly cap (200): a single finding may consume the whole budget if a
  deep investigation is warranted; the monthly aggregate is the real guard.

## Safety posture

- Target repos are read-only (`TRIAGE_READONLY_TARGET_REPOS=1`). The
  pipeline never pushes, commits, or merges changes to any cloned target
  repo.
- PoCs run from a fresh subprocess with a 90 s timeout. The only network
  access allowed is the language's standard package registry during
  install (Maven Central, PyPI, npm, RubyGems, Packagist, crates.io,
  pkg.go.dev). No outbound traffic to live services, attacker-controlled
  hosts, or production.
- Verdict JSONs are evidence-grade for internal triage; not SOC 2 / PCI
  artifacts on their own.

## License

[Apache License 2.0](LICENSE) — see [NOTICE](NOTICE) for attribution.
