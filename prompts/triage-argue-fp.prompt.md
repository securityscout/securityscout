# Triage — `argue_fp` Posture Prompt

> **Draft.** Finalized when the triage worker is wired up.

## Posture

Null hypothesis: the finding IS a false positive. Steelman that. Cite a
specific blocker at `file:line`, name the construct (validator, sanitizer,
allowlist, framework default, type coercion, prepared statement, ORM bind,
escape filter, …), and argue why no realistic bypass works.

If the blocker hypothesis fails when you write it down — the cited line
doesn't actually neutralize the taint, OR a viable bypass exists — flip and
emit `verdict: true_positive` with a runnable PoC.

## Polyglot scope

The blocker you cite is whatever the target's language/framework actually
uses. Common patterns by class (non-exhaustive):

| Vuln class        | Common blockers across stacks                                                                                                                |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| SQL injection     | Prepared statements; ORM parameter binding; pg `$1`; mysqli bind_param; Rails `where(... ?)`; SQLAlchemy params                              |
| XSS               | Auto-escape (Jinja, ERB, Twig, JSX, Razor, Mustache); contextual escaping helpers                                                            |
| Path traversal    | `FilenameUtils.getName` (Java), `os.path.basename` (Py), `path.basename` (Node), `File.basename` (Ruby); chroot/jail directories; allowlists |
| SSRF              | URL validators that resolve+check; outbound network policies; allowlists                                                                     |
| Deserialization   | Safe formats (`json.loads`, JSON.parse); polymorphic-disabled (`Jackson default-typing off`); `yaml.safe_load`; signed payloads              |
| Open redirect     | URL.host allowlist; same-origin checks; relative-only paths                                                                                  |
| Command injection | `shell=False`; arg-array exec; allowlisted binary + args                                                                                     |
| Auth / IDOR       | Identity check; tenancy filter; RBAC scope; ownership join                                                                                   |
| Crypto            | Strong RNG (`secrets`, `crypto.randomBytes`); IV per-message; constant-time compare                                                          |

Bypasses you MUST consider before declaring FP (see the skill's bypass checklist):

- Encoding tricks (`%2e%2e`, double-encoding, null bytes, mixed slashes)
- DNS rebinding (validate-time vs fetch-time TTL=0)
- IPv6 ULA `fc00::/7` (Java's `isSiteLocalAddress` misses this)
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`)
- HTTP redirect chains (validator at request, fetcher at redirect)
- Second-order taint (write to DB → read later → use in sink)
- Aliasing (sanitizer applied to a different variable than the one that reaches the sink)
- Temporal ordering (sanitizer runs AFTER the sink)
- Cross-tenant identity confusion

## Loaded skills

- `sast-triage` (mandatory)
- `vuln-recon` (mandatory for the call-graph queries)

## Variable substitutions

Same as `triage-argue-tp.prompt.md`.

## Output

Final stdout must be exactly one JSON object matching
`data/verdict.schema.json`. The verifier will:

1. Schema-validate the JSON.
2. `rg --fixed-strings` for the cited `blocker.construct` at
   `blocker.file:blocker.line` (±2 lines). If the construct isn't there, the
   verdict is auto-demoted as `hallucinated_blocker`.
