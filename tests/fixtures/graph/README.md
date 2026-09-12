# Canned chain transcript

`session-admin.json` is the shape `triage.http_session.capture_http`
returns, so `chain.seed_two_hop` can store the hop's evidence without
sending a request.

`seed_two_hop` re-serialises it through `gateway.canonical_json_bytes`
and writes it as `transcripts/<sha256>.json`, so the bytes on disk are
the bytes `tool_spans.result_sha256` covers.

The hop it evidences is a leaked session reused against an admin
endpoint. The request carries a placeholder cookie and the response is
an ordinary admin listing — the evidence is that the endpoint answered
at all. No exploit payload is stored in this repo.
