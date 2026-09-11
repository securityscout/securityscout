# Canned hunt transcripts

`injection-search.json` is the shape `triage.http_session.capture_http`
returns — request, response status/headers/body excerpt, timing — so the
acceptance run proves the merge and the verifier hash-check without
sending a request.

`run_fixture` re-serialises it through `gateway.canonical_json_bytes` and
writes it as `<sha256>.json`, the same naming
`http_session.gateway_execute` uses, so the bytes on disk are the bytes
`tool_spans.result_sha256` covers.

The request is a plain `GET` with an ordinary search term. The evidence
is the response: the service echoes the assembled SQL, which is what
makes the concatenation at `app/db.py:12` observable from outside. No
exploit payload is stored in this repo.
