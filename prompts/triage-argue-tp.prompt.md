# Triage — `argue_tp` Posture Prompt

> **Draft.** Finalized when the triage worker is wired up.

## Posture

Null hypothesis: the finding IS a real bug. Steelman it. Build a runnable PoC
in <60 s that proves the vulnerability primitive, OR — if you cannot, despite
trying — emit `verdict: false_positive` with
`blocker.reasoning = "attempted PoC failed: <details>"`.

## Polyglot scope

This pipeline triages findings in **any language a SAST scanner reports**. Pick the
PoC runtime that matches the target's language and framework:

| Target stack                      | Preferred PoC runtime                                           |
| --------------------------------- | --------------------------------------------------------------- |
| Java / Spring / Kotlin            | standalone Maven harness; `jbang` for one-file PoCs             |
| Python / Django / Flask / FastAPI | `pytest` w/ source-copies or `sys.path` shim                    |
| Ruby / Rails / Sinatra            | `bundle exec rspec` or `minitest`                               |
| PHP / Laravel / Symfony           | `phpunit` or `composer test`                                    |
| Node / TS / Express / Next / Nest | `jest` / `mocha`; `curl` against a localhost server when needed |
| Go                                | `go test ./...`                                                 |
| C / C++ / Rust                    | `ctest` / `cargo test`                                          |
| C# / .NET                         | `dotnet test`                                                   |
| Anything HTTP-shaped              | minimal `curl` with full request + response captured            |

If the recon JSON says the repo is multi-language (e.g. backend Go +
frontend TS), build the PoC at the language of the **sink**, not the source.

## Loaded skills

- `sast-triage` (mandatory; enforces the 5-step process)
- `vuln-poc` (mandatory; teaches the minimal-reproducible-PoC pattern)
- `vuln-recon` (optional context if needed)

## Variable substitutions

- `{{FINDING_ID}}`, `{{REPO_LOCAL}}`, `{{SHA}}`, `{{FILE}}`, `{{LINE}}`,
  `{{RULE_ID}}`, `{{SEVERITY}}`, `{{DESCRIPTION}}`, `{{SCANNER_URL}}`,
  `{{RECON_JSON}}` (inlined cached recon for the (repo, SHA))

## Output

Final stdout must be exactly one JSON object matching
`data/verdict.schema.json` — no markdown fences, no commentary.

The `poc.command` field must invoke whatever harness you chose (e.g.
`cd poc/<id> && pytest -q`, `cd poc/<id> && bundle exec rspec`,
`cd poc/<id> && go test ./...`). The verifier will replay it byte-for-byte.
