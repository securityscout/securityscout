# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from urllib.parse import urlencode

import pytest

from webhooks.slack import (
    SlackActionId,
    SlackVerificationError,
    SlackWebhookProvider,
    parse_interactive_payload,
)

_PROVIDER = SlackWebhookProvider()
_SECRET = "shhh-signing-secret"


def _sign(ts: str, body: bytes, secret: str = _SECRET) -> str:
    basestring = b"v0:" + ts.encode("utf-8") + b":" + body
    mac = hmac.new(secret.encode("utf-8"), basestring, hashlib.sha256)
    return "v0=" + mac.hexdigest()


def test_verify_signature_accepts_canonical_slack_example() -> None:
    # Mirrors Slack's published verification recipe.
    ts = str(int(time.time()))
    body = b"token=xoxb&team_id=T0001"
    sig = _sign(ts, body)
    _PROVIDER.verify_signature(
        body,
        {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts},
        _SECRET,
    )


def test_verify_signature_rejects_tampered_body() -> None:
    ts = str(int(time.time()))
    body = b"payload=1"
    sig = _sign(ts, body)
    with pytest.raises(SlackVerificationError, match="invalid Slack signature"):
        _PROVIDER.verify_signature(
            body + b"!",
            {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts},
            _SECRET,
        )


def test_verify_signature_requires_headers() -> None:
    with pytest.raises(SlackVerificationError, match="X-Slack-Signature"):
        _PROVIDER.verify_signature(b"", {}, _SECRET)
    with pytest.raises(SlackVerificationError, match="Timestamp"):
        _PROVIDER.verify_signature(b"", {"X-Slack-Signature": "v0=deadbeef"}, _SECRET)


def test_assert_delivery_fresh_rejects_stale_timestamp() -> None:
    now = time.time()
    stale = str(int(now - 1000))
    with pytest.raises(SlackVerificationError, match="stale"):
        _PROVIDER.assert_delivery_fresh(
            {"X-Slack-Request-Timestamp": stale},
            now=_dt_from_epoch(now),
        )


def test_assert_delivery_fresh_rejects_future_skew() -> None:
    now = time.time()
    future = str(int(now + 1000))
    with pytest.raises(SlackVerificationError, match="future"):
        _PROVIDER.assert_delivery_fresh(
            {"X-Slack-Request-Timestamp": future},
            now=_dt_from_epoch(now),
        )


def test_assert_delivery_fresh_rejects_malformed_timestamp() -> None:
    with pytest.raises(SlackVerificationError, match="invalid"):
        _PROVIDER.assert_delivery_fresh(
            {"X-Slack-Request-Timestamp": "not-a-number"},
            now=_dt_from_epoch(time.time()),
        )


def _dt_from_epoch(epoch: float):
    from datetime import UTC, datetime

    return datetime.fromtimestamp(epoch, tz=UTC)


def _encoded_button_value() -> str:
    return f"{uuid.uuid4()}|{uuid.uuid4()}|demo"


def test_parse_interactive_payload_decodes_approve_action() -> None:
    value = _encoded_button_value()
    payload = {
        "type": "block_actions",
        "user": {"id": "U01ABC"},
        "container": {"type": "message", "message_ts": "1111.2222", "channel_id": "C123"},
        "channel": {"id": "C123"},
        "actions": [
            {
                "action_id": "security_scout:approve",
                "value": value,
                "type": "button",
            }
        ],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    out = parse_interactive_payload(body)
    assert out.action == SlackActionId.approve
    assert out.user_id == "U01ABC"
    assert out.channel_id == "C123"
    assert out.message_ts == "1111.2222"
    assert out.button_value == value


def test_parse_interactive_payload_rejects_unknown_action() -> None:
    payload = {
        "type": "block_actions",
        "user": {"id": "U01"},
        "container": {"message_ts": "1.0", "channel_id": "C1"},
        "actions": [{"action_id": "not_ours", "value": "v", "type": "button"}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="unknown action_id"):
        parse_interactive_payload(body)


def test_parse_interactive_payload_rejects_non_block_actions() -> None:
    payload = {"type": "view_submission"}
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="unsupported"):
        parse_interactive_payload(body)


def test_parse_interactive_payload_requires_payload_field() -> None:
    with pytest.raises(SlackVerificationError, match="missing payload"):
        parse_interactive_payload(b"other=thing")


def test_assert_delivery_fresh_requires_timestamp_header() -> None:
    with pytest.raises(SlackVerificationError, match="Timestamp"):
        _PROVIDER.assert_delivery_fresh({}, now=_dt_from_epoch(time.time()))


def test_parse_interactive_payload_rejects_invalid_utf8_body() -> None:
    with pytest.raises(SlackVerificationError, match="invalid form"):
        parse_interactive_payload(b"payload=\xff\xfe")


def test_parse_interactive_payload_rejects_invalid_json() -> None:
    body = urlencode({"payload": "not json"}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="invalid payload JSON"):
        parse_interactive_payload(body)


def test_parse_interactive_payload_rejects_non_object_json() -> None:
    body = urlencode({"payload": json.dumps(["x"])}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="not a JSON object"):
        parse_interactive_payload(body)


def test_parse_interactive_payload_rejects_empty_actions() -> None:
    payload = {
        "type": "block_actions",
        "user": {"id": "U1"},
        "container": {"message_ts": "1.0", "channel_id": "C1"},
        "actions": [],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="missing actions"):
        parse_interactive_payload(body)


def test_parse_interactive_payload_rejects_non_dict_action() -> None:
    payload = {
        "type": "block_actions",
        "user": {"id": "U1"},
        "container": {"message_ts": "1.0", "channel_id": "C1"},
        "actions": ["nope"],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="malformed action entry"):
        parse_interactive_payload(body)


def test_parse_interactive_payload_rejects_bad_action_field_types() -> None:
    payload = {
        "type": "block_actions",
        "user": {"id": "U1"},
        "container": {"message_ts": "1.0", "channel_id": "C1"},
        "actions": [{"action_id": 1, "value": "v"}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="malformed action fields"):
        parse_interactive_payload(body)


def test_parse_interactive_payload_rejects_missing_user() -> None:
    payload = {
        "type": "block_actions",
        "container": {"message_ts": "1.0", "channel_id": "C1"},
        "actions": [{"action_id": "security_scout:approve", "value": _encoded_button_value()}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="missing user"):
        parse_interactive_payload(body)


def test_parse_interactive_payload_rejects_bad_user_id() -> None:
    payload = {
        "type": "block_actions",
        "user": {"id": ""},
        "container": {"message_ts": "1.0", "channel_id": "C1"},
        "actions": [{"action_id": "security_scout:approve", "value": _encoded_button_value()}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="missing user id"):
        parse_interactive_payload(body)


def test_parse_interactive_payload_takes_channel_id_from_channel_only() -> None:
    value = _encoded_button_value()
    payload = {
        "type": "block_actions",
        "user": {"id": "U1"},
        "container": {"message_ts": "9.9"},
        "channel": {"id": "C-from-channel"},
        "actions": [{"action_id": "security_scout:approve", "value": value}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    out = parse_interactive_payload(body)
    assert out.channel_id == "C-from-channel"
    assert out.message_ts == "9.9"


def test_parse_interactive_payload_requires_channel_and_message_ts() -> None:
    value = _encoded_button_value()
    payload = {
        "type": "block_actions",
        "user": {"id": "U1"},
        "container": {},
        "actions": [{"action_id": "security_scout:approve", "value": value}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    with pytest.raises(SlackVerificationError, match="missing channel or message_ts"):
        parse_interactive_payload(body)


@pytest.mark.parametrize(
    "action_id",
    [
        "security_scout:dedup_confirm",
        "security_scout:dedup_new_instance",
        "security_scout:dedup_reopen",
        "security_scout:dedup_resolved",
        "security_scout:risk_still_accepted",
        "security_scout:risk_reevaluate",
    ],
)
def test_parse_interactive_payload_decodes_dedup_actions(action_id: str) -> None:
    value = _encoded_button_value()
    payload = {
        "type": "block_actions",
        "user": {"id": "U01ABC"},
        "container": {"message_ts": "1.0", "channel_id": "C1"},
        "actions": [{"action_id": action_id, "value": value, "type": "button"}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    out = parse_interactive_payload(body)
    assert out.action.value == action_id
    assert out.button_value == value


@pytest.mark.parametrize(
    "action_id",
    [
        "security_scout:preflight_proceed",
        "security_scout:preflight_cancel",
        "security_scout:run_patch_oracle",
    ],
)
def test_parse_interactive_payload_decodes_workflow_aux_actions(action_id: str) -> None:
    value = _encoded_button_value()
    payload = {
        "type": "block_actions",
        "user": {"id": "U01ABC"},
        "container": {"message_ts": "1.0", "channel_id": "C1"},
        "actions": [{"action_id": action_id, "value": value, "type": "button"}],
    }
    body = urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    out = parse_interactive_payload(body)
    assert out.action.value == action_id
    assert out.button_value == value
