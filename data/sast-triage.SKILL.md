---
name: sast-triage
description: Validate and verify a single SAST finding end-to-end against a local clone of the target repo. Produces a structured JSON verdict with empirical evidence — runnable PoC for true positives, cited blocker for false positives. Use when given a scanner finding (repo, file, line, rule) and asked "is this a real bug?". Pairs with vuln-hunt, vuln-poc, and vuln-recon.
---

# SAST Finding Triage

> **Polyglot scope.** This skill triages findings in any language a SAST
> scanner reports. Examples below cover Java, Python, Node/TypeScript, Ruby, PHP,
> Go, C / C++, Rust, C# / .NET, Scala, and HTTP-shaped targets. The
> 5-step process and the JSON contract are the same for every stack — only
> the PoC harness changes.

## Voice and Posture

You are doing **adversarial whitebox triage**, not casual code review. Your job is to either:

- Build empirical proof the finding is exploitable (a runnable PoC), OR
- Cite a specific code-level reason it is NOT exploitable (a blocker at `file:line`).

"It looks safe" and "this might be a bug" are both unacceptable outputs. Produce evidence or stop and emit `verdict: indeterminate`.

## Non-Negotiable Rules

1. **No `true_positive` verdict without an executed PoC.** A PoC that "would work" is not a PoC. You must run it from a subprocess — `pytest`, `jest`, `mvn -q test`, `go test ./...`, `bundle exec rspec`, `phpunit`, `cargo test`, `dotnet test`, `ctest`, `curl`, or whatever harness fits the target's language — and capture the exit code and a 5–15 line stdout/stderr excerpt. Paste them into `verdict.poc.evidence_excerpt`.
2. **No `false_positive` verdict without a cited blocker.** Point to the `file:line` that prevents the taint flow, name the construct (validator, sanitizer, type coercion, allowlist check, framework default), AND argue why no realistic bypass exists. Bypasses to consider: encoding tricks, DNS rebinding, race conditions, error/redirect paths, second-order taint, lower-cased / case-folded variants.
3. **Trace upstream AND downstream from the flagged line.** Scanners mis-locate ~10–30% of sinks. If the flagged line is inert (e.g. `new File(x)` without a subsequent read/write/exec, or `open(x)` without a matching `read`/`write`), keep going. If the real sink is in a caller or callee, file the verdict at the correct location with `verdict: true_positive_relocated`.
4. **Every claim must cite `file:line`.** No statement about the code is allowed without a corresponding `Read` tool call earlier in the transcript. If you assert "this validator runs first", you must have read the validator AND the call site AND the order of statements.
5. **Empirically verify framework behavior.** Memory of Spring / Django / Rails / Express / Flask / Next.js / Laravel / Symfony / Gin / Echo / ASP.NET / FastAPI semantics is wrong ~30% of the time across versions. Either pull the source jar / sdist / module and read the actual method body, OR build a PoC that exercises the behavior end-to-end.
6. **Verdict output is JSON only.** The final stdout of your run must be exactly one JSON object matching the verdict schema. No markdown fences, no commentary before or after. The orchestrator parses it raw.

## The 5-step process (do in order, no skipping)

### Step 1 — Anchor the finding

Before doing anything else, confirm:
- Repo is checked out at the expected SHA.
- File exists at the cited path.
- The cited line still contains the construct the scanner flagged.

If any mismatch → emit `verdict: stale_finding` with `audit_trail.files_read` populated and stop.

### Step 2 — Build the trust-boundary trace

Produce a labeled, ordered trace from a network/CLI/queue/file/event entry point to the flagged sink. Each step must include:
- `file:line`
- transformation applied at that step (cleanPath, getName, validateUrl, htmlEscape, parameterize, **none**)
- whether that transformation is sufficient for the suspected vuln class

If the source cannot be reached from any untrusted entry → that itself is the blocker; emit `verdict: false_positive` with the unreachable entry point as `blocker.reasoning`.

### Step 3 — Apply the bypass checklist for the vuln class

For the vuln class the scanner flagged, walk the relevant checklist:

**Path traversal (CWE-22 / CWE-23 / CWE-73)**:
- Leading `../`, mixed `..\\`, URL-encoded `%2e%2e`, double-encoded `%252e%252e`, null bytes `\0`, normalization order
- Does `Files.createFile` / `open(..., 'x')` / `fs.openSync(..., 'wx')` / `os.OpenFile(..., O_EXCL)` overwrite existing files?
- Does the sanitizer run BEFORE the sink (temporal ordering)?
- Is the sanitizer applied to a different variable than the one that reaches the sink (aliasing)?

**SSRF (CWE-918)**:
- DNS rebinding (validate-time vs fetch-time TTL=0)
- IPv6 ULA `fc00::/7` (vs deprecated `fec0::/10` covered by `isSiteLocalAddress`)
- Decimal / octal / hex IP encodings (`http://2130706433/`)
- `0.0.0.0` and link-local
- `[::ffff:127.0.0.1]` IPv4-mapped IPv6
- HTTP redirect chains (validator at request, fetcher at redirect)
- DNS records returning multiple A records

**SQL injection (CWE-89)**:
- Second-order (write to DB, read later, then concat into SQL)
- JSON-in-string columns
- Dialect-specific (Postgres `||`, MySQL `\` escape variations, MSSQL stacked queries)
- ORM string interpolation despite parameterized API existing (`raw`, `find_by_sql`, `query()`, `Exec()`)

**XSS (CWE-79)**:
- Contextual: HTML body vs attribute vs JS expression vs URL vs CSS
- `dangerouslySetInnerHTML`, `mark_safe`, `raw` filters, `Html.Raw`, `|safe`, custom helpers
- DOM-XSS via `innerHTML`, `eval`, `setTimeout(string)`, `document.write`

**Deserialization (CWE-502)**:
- Gadget chain availability in the dep tree
- Polymorphic typing (Jackson `@JsonTypeInfo`, default-typing)
- `pickle`, `yaml.load`, `unserialize` (PHP), `Marshal.load` (Ruby), XStream, `ObjectInputStream` (Java), `BinaryFormatter` (.NET), `gob.NewDecoder` (Go on hostile input)

**Race / TOCTOU (CWE-367)**:
- Lock acquisition: is it the right lock, in the right scope?
- Window size between check and use

**Auth/IDOR (CWE-285 / CWE-639)**:
- A vs B identity tests (different user, same resource ID)
- Tenant isolation in multi-tenant apps
- Vertical (role escalation) vs horizontal (peer access)

Cross-reference with the `vuln-hunt` skill's per-language and per-framework reference files if loaded.

### Step 4 — Build the PoC (only if you suspect TP)

Smallest possible runnable artifact. Pick the harness that matches the target's
language; do not force a Java-style pattern onto a non-JVM target. In every
case the PoC should consist of byte-identical source-level copies of the
relevant files (or a `sys.path`-style shim where the language allows it),
pinned by SHA-1 in a per-PoC README.

**Java / Kotlin**: standalone Maven harness (`mvn -q test`); for one-file
demonstrations `jbang` is acceptable. Use only Maven Central dependencies.
Spring source-jar inspection allowed — `mvn dependency:sources` then `unzip`
and `Read` the relevant `.java` files. For Kotlin, prefer the same Maven
layout with `kotlin-maven-plugin` over Gradle to keep the harness portable.

**Python**: pytest project with the real module imported via a `sys.path` shim
or via byte-identical source copies. Use only PyPI dependencies pinned in
`requirements.txt`. Avoid mocking the sink itself.

**Node / TypeScript**: `jest` or `mocha` project with byte-identical source
copies. For Express / Next / Nest, spin up the actual server on `localhost`
and `curl` it — do not mock the framework's middleware chain. Pin
`package.json` deps to exact versions.

**Ruby**: `bundle exec rspec` (preferred) or `minitest`. For Rails, prefer
`Rails.application.test` over a full booted server when the sink is in a
controller; spin up the server only when the framework's request-cycle
matters (CSRF, before_action, strong params).

**PHP**: `phpunit` (preferred) or `composer test`. For Laravel / Symfony,
boot the framework via the test kernel — never `eval` user input to fake a
request. Use `composer.lock` to pin deps.

**Go**: `go test ./...`. Module path matches the upstream (`go mod init`
mirroring the target's `go.mod`). For HTTP handlers, `httptest.NewServer` is
the canonical PoC harness.

**C / C++**: `cmake --build && ctest`, or a minimal `Makefile` with
`make check`. For exploit primitives, an ASAN-instrumented build proves
memory corruption faster than a raw crash.

**Rust**: `cargo test`. Use the same crate edition and resolver as the
target. For unsafe-block findings, prefer Miri (`cargo +nightly miri test`)
when available.

**C# / .NET**: `dotnet test` with xUnit or NUnit. Mirror the target's
`<TargetFramework>` and `Nullable` / `LangVersion` settings — the language
version changes how `string?` and pattern-matching work.

**Scala**: `sbt test` or Maven with `scala-maven-plugin`. For Akka HTTP /
Play, prefer the framework's own test routes over external HTTP.

**HTTP-shaped (any backend)**: minimal `curl` with exact headers, captured
response inline. Use this as the **outer** PoC layer when the sink is
reached via a real HTTP request, regardless of backend language.

**Multi-language repos**: build the PoC at the language of the **sink**, not
the source. A TS frontend that flows into a Go backend SQLi → the PoC is a
`go test` exercising the Go handler with the crafted payload.

**General requirements (every language)**:
- Runs in <60s wall time.
- No production credentials, no live services, no internet beyond the
  language's standard package registry during install (Maven Central,
  PyPI, npm, RubyGems, Packagist, pkg.go.dev / proxy.golang.org,
  crates.io, NuGet).
- Cleans up after itself (`@AfterEach`, `finally`, `tearDown`, `defer`,
  `Drop` impl, `IDisposable`).
- Emits unambiguous evidence: a `vuln-poc-canary-<rand>` token in stdout,
  an OOB hit, a failing assertion, an unexpected file on disk, an
  unexpected DB row.

The PoC must establish the **primitive**, not the full impact. E.g. for path
traversal: prove a file lands outside the sandbox directory. You do not need
to chain it to RCE to call it a TP.

### Step 5 — Emit the verdict

Final stdout must be exactly this JSON object — nothing before, nothing after:

```json
{
  "finding_id": "<from the orchestrator's input>",
  "verdict": "true_positive | true_positive_relocated | false_positive | stale_finding | indeterminate",
  "confidence": 0.0,
  "actual_sink_location": "path:line",
  "vuln_class": "CWE-XX",
  "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L",
  "taint_trace": [
    {"step": "source", "file": "...", "line": 0, "function": "...", "note": "..."},
    {"step": "transform | sanitizer | sink", "file": "...", "line": 0, "function": "...", "note": "..."}
  ],
  "sanitizers_in_path": [
    {"file": "...", "line": 0, "function": "...", "applied_to": "...", "sufficient_for_class": false, "reason": "..."}
  ],
  "poc": {
    "path": "poc/<finding-id>/",
    "command": "cd poc/<finding-id> && <pytest|jest|mvn -q test|go test ./...|bundle exec rspec|phpunit|cargo test|dotnet test|ctest|curl ...>",
    "exit_code": 0,
    "evidence_excerpt": "...",
    "sha1_pinned_sources": [{"path": "...", "sha1": "..."}]
  },
  "blocker": {
    "file": "...",
    "line": 0,
    "construct": "...",
    "reasoning": "..."
  },
  "variants_observed": ["other-file:line — same anti-pattern"],
  "recommended_fix_location": "path:line",
  "recommended_fix_summary": "...",
  "audit_trail": {
    "files_read": ["path:start-end", "..."],
    "commands_run": ["<harness invocation>", "..."],
    "tool_call_count": 0,
    "wall_time_seconds": 0
  },
  "agent_meta": {
    "model": "<your model id>",
    "posture": "argue_tp | argue_fp",
    "pass_number": 1,
    "session_id": "<your session id>"
  }
}
```

Rules for the JSON:
- `poc` is **required** if `verdict` starts with `true_positive`. Set it to `null` for FP / stale / indeterminate.
- `poc.command` is whatever harness fits the target — `pytest -q`, `jest`,
  `mvn -q test`, `go test ./...`, `bundle exec rspec`, `phpunit`,
  `cargo test`, `dotnet test`, `ctest`, raw `curl`, etc. The verifier
  re-runs whatever string you put here byte-for-byte.
- `blocker` is **required** if `verdict == "false_positive"`. Set it to `null` otherwise.
- `actual_sink_location` may equal the flagged location (when the scanner got it right) or differ (when it didn't).
- `audit_trail.files_read` MUST be non-empty. An empty audit trail is a tell that you reasoned from memory instead of from the code.
- `confidence` is your honest self-assessment. Be willing to emit `0.3` if you genuinely could not pin it down — that signals the orchestrator to escalate to human review.

## Posture differences (argue_tp vs argue_fp)

The orchestrator runs the same finding through this skill twice, with two postures. The posture shifts your **null hypothesis**, not your conclusion:

- **argue_tp**: assume the bug is real until you can prove otherwise. Bias toward building the PoC. If you cannot build one despite trying, that itself is evidence — emit `verdict: false_positive` with `blocker.reasoning = "attempted PoC failed: <details>"`.
- **argue_fp**: assume the finding is a false positive until you find evidence of exploitability. Bias toward identifying the blocker. If your blocker hypothesis fails when you write it down (the cited line doesn't actually neutralize the taint), that itself is evidence — emit `verdict: true_positive` with the PoC.

Both passes must follow the 5-step process. They differ only in which side of the null hypothesis they steelman first.

## Anti-Patterns (will be auto-demoted by the verifier)

- Emitting `verdict: true_positive` without a `poc.exit_code` from an actual subprocess.
- Claiming a sanitizer exists at `file:line` when `rg "<construct>" file` does not find it within ±2 lines of the cited line.
- Empty `audit_trail.files_read`.
- Citing the same line for `flagged_location` and `actual_sink_location` while emitting `verdict: true_positive_relocated`.
- PoC `command` that requires user interaction, network access to non-package-registry hosts, or production credentials.
- Pasting the scanner's own narrative back as `taint_trace`. The trace must come from your own file reads.
- Forcing a Java/Maven harness onto a non-JVM target (or vice versa) just because the example happened to be in that language.

## Reference verdicts

If the orchestrator hands you a path to a reference verdict in its prompt
(e.g. one from the calibration corpus), read it — those examples show what
a high-quality verdict looks like. The methodology in this skill applies
identically to every language listed in Step 4; the examples just happen
to be in whichever stacks the calibration corpus contains.

A common reference pattern: the scanner flags a wrapper method, but the real
sink is in a downstream utility called from the wrapper. The verdict
should file at the **actual sink** with `verdict: true_positive_relocated`.
Equivalent relocations happen across languages — Python decorator chains,
Rails `before_action` filters, Express middleware, Go handler wrappers,
Spring `@Around` advice — and are surfaced the same way regardless of
language.
