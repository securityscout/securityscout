# photoview-class fixture

A three-file media gallery with the shape hunt mode targets: an HTTP
entry point that reads a query parameter and a data-access sink that
concatenates it into SQL. It stands in for a Photoview-class app so the
acceptance run needs no vendored upstream tree and no clone.

The tree is never executed. Tests read `app/api.py` and `app/db.py` only
as entry/sink locations, so their line numbers are part of the fixture
contract — `triage.hunt.FIXTURE_ENTRY_LINE` / `FIXTURE_SINK_LINE` pin
them.

No exploit payload lives here or in `../transcripts/`: the canned proof
is a plain `GET` whose response body echoes the assembled query.
