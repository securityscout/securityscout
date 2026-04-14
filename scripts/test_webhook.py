#!/usr/bin/env python3
"""Send a simulated GitHub repository_advisory webhook to the local server.

Signs the payload with the same secret configured in .env so the HMAC check
passes.  Uses a real DHIS2 advisory (GHSA-fj38-585h-hxgj — SQL Injection in
Tracker API, CVSS 8.6) as test data.

Usage:
    uv run python scripts/test_webhook.py
    # or with a custom URL:
    uv run python scripts/test_webhook.py --url http://127.0.0.1:8000/webhooks/github
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime
from email.utils import format_datetime

import httpx

WEBHOOK_SECRET = "local-test-secret-do-not-use-in-prod"
DEFAULT_URL = "http://127.0.0.1:8000/webhooks/github"

PAYLOAD = {
    "action": "published",
    "repository_advisory": {
        "ghsa_id": "GHSA-fj38-585h-hxgj",
        "cve_id": "CVE-2021-39179",
        "summary": "SQL Injection in DHIS2 Tracker API",
        "description": (
            "A SQL injection vulnerability was found in the `/api/trackedEntityInstances` "
            "endpoint of DHIS2. An authenticated user with access to the Tracker API could "
            "craft a specially formed request parameter that results in arbitrary SQL execution. "
            "Affected versions: 2.34.4, 2.35.2-2.35.4, 2.36.0. Patched in 2.34.5, 2.35.5, 2.36.1."
        ),
        "severity": "high",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "dhis2", "name": "dhis2-core"},
                "vulnerable_version_range": ">= 2.34.4, < 2.36.1",
                "patched_versions": "2.34.5, 2.35.5, 2.36.1",
            }
        ],
        "cvss": {
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "score": 8.6,
        },
        "cwes": [{"cwe_id": "CWE-89", "name": "SQL Injection"}],
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-fj38-585h-hxgj"},
            {"type": "CVE", "value": "CVE-2021-39179"},
        ],
        "published_at": "2021-10-01T12:00:00Z",
        "updated_at": "2021-10-01T12:00:00Z",
    },
    "repository": {
        "id": 16800037,
        "name": "dhis2-core",
        "full_name": "dhis2/dhis2-core",
        "owner": {"login": "dhis2", "id": 6902207},
        "html_url": "https://github.com/dhis2/dhis2-core",
        "description": "DHIS2 core application",
        "private": False,
    },
    "organization": {"login": "dhis2", "id": 6902207},
    "sender": {"login": "security-bot", "id": 1},
}


def sign_payload(body: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Send simulated GitHub advisory webhook")
    parser.add_argument("--url", default=DEFAULT_URL, help="Webhook endpoint URL")
    parser.add_argument("--secret", default=WEBHOOK_SECRET, help="Webhook HMAC secret")
    args = parser.parse_args()

    body = json.dumps(PAYLOAD).encode()
    signature = sign_payload(body, args.secret)
    delivery_id = str(uuid.uuid4())

    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "repository_advisory",
        "X-GitHub-Delivery": delivery_id,
        "X-Hub-Signature-256": signature,
        "Date": format_datetime(datetime.now(UTC), usegmt=True),
    }

    print(f"Sending repository_advisory webhook to {args.url}")
    print("  GHSA: GHSA-fj38-585h-hxgj (SQL Injection in DHIS2 Tracker API)")
    print(f"  Delivery ID: {delivery_id}")
    print(f"  Signature: {signature[:30]}...")
    print()

    resp = httpx.post(args.url, content=body, headers=headers)
    print(f"Response: {resp.status_code}")
    if resp.text:
        print(f"Body: {resp.text}")

    if resp.status_code == 202:
        print("\nWebhook accepted! The advisory has been enqueued for triage.")
        print("Check the ARQ worker terminal for processing output.")
    elif resp.status_code == 401:
        print("\nHMAC verification failed — check GITHUB_WEBHOOK_SECRET in .env")
    else:
        print(f"\nUnexpected status: {resp.status_code}")


if __name__ == "__main__":
    main()
