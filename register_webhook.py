"""
Script to register/unregister a webhook with an OpenWA instance.
Run once per workspace/client to point OpenWA at the relay.

Usage:
    python register_webhook.py register \\
        --openwa-url https://openwa-api-production.up.railway.app \\
        --session-id sess_abc123 \\
        --api-key owa_xxx \\
        --relay-url https://relay-acme.up.railway.app \\
        --secret your-shared-secret

    python register_webhook.py list \\
        --openwa-url ... --session-id ... --api-key ...

    python register_webhook.py unregister \\
        --openwa-url ... --session-id ... --api-key ... --webhook-id wh_xxx
"""

import argparse
import json
import sys

import httpx


def register_webhook(
    openwa_url: str,
    session_id: str,
    api_key: str,
    relay_url: str,
    secret: str,
    events: list[str] = None,
) -> dict:
    """Register a webhook with OpenWA pointing to the relay."""
    url = f"{openwa_url.rstrip('/')}/api/sessions/{session_id}/webhooks"

    if events is None:
        events = ["message.received"]

    body = {
        "url": relay_url,
        "events": events,
        "secret": secret,
    }

    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }

    try:
        resp = httpx.post(url, json=body, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        print(f"Error {e.response.status_code}: {e.response.text}", file=sys.stderr)
        sys.exit(1)


def list_webhooks(openwa_url: str, session_id: str, api_key: str) -> list[dict]:
    """List all webhooks registered for a session."""
    url = f"{openwa_url.rstrip('/')}/api/sessions/{session_id}/webhooks"

    headers = {"X-API-Key": api_key}

    try:
        resp = httpx.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", [])
    except httpx.HTTPStatusError as e:
        print(f"Error {e.response.status_code}: {e.response.text}", file=sys.stderr)
        sys.exit(1)


def unregister_webhook(
    openwa_url: str,
    session_id: str,
    api_key: str,
    webhook_id: str,
) -> dict:
    """Delete a single webhook from a session."""
    url = f"{openwa_url.rstrip('/')}/api/sessions/{session_id}/webhooks/{webhook_id}"

    headers = {"X-API-Key": api_key}

    try:
        resp = httpx.delete(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        print(f"Error {e.response.status_code}: {e.response.text}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="OpenWA Webhook Registration")
    sub = parser.add_subparsers(dest="command", required=True)

    # register
    reg = sub.add_parser("register", help="Register a new webhook")
    reg.add_argument("--openwa-url", required=True)
    reg.add_argument("--session-id", required=True)
    reg.add_argument("--api-key", required=True)
    reg.add_argument("--relay-url", required=True, help="URL of the relay service (e.g. https://relay-acme.up.railway.app/webhook)")
    reg.add_argument("--secret", required=True, help="HMAC secret (must match OPENWA_WEBHOOK_SECRET in relay)")
    reg.add_argument("--events", nargs="*", default=["message.received"])

    # list
    lst = sub.add_parser("list", help="List registered webhooks")
    lst.add_argument("--openwa-url", required=True)
    lst.add_argument("--session-id", required=True)
    lst.add_argument("--api-key", required=True)

    # unregister
    unreg = sub.add_parser("unregister", help="Delete a webhook")
    unreg.add_argument("--openwa-url", required=True)
    unreg.add_argument("--session-id", required=True)
    unreg.add_argument("--api-key", required=True)
    unreg.add_argument("--webhook-id", required=True)

    args = parser.parse_args()

    if args.command == "register":
        result = register_webhook(
            args.openwa_url, args.session_id, args.api_key,
            args.relay_url, args.secret, args.events,
        )
        print(json.dumps(result, indent=2))

    elif args.command == "list":
        webhooks = list_webhooks(args.openwa_url, args.session_id, args.api_key)
        if not webhooks:
            print("No webhooks registered.")
        else:
            for wh in webhooks:
                print(json.dumps(wh, indent=2))

    elif args.command == "unregister":
        result = unregister_webhook(
            args.openwa_url, args.session_id, args.api_key, args.webhook_id,
        )
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
