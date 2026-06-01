"""
OpenWA Webhook Relay
====================
Receives OpenWA webhooks, verifies HMAC signature, transforms the
payload to the format expected by the lev-agent-demo backend, and
forwards to /webhooks/execute/{workspace_id} for direct flow bypass.

Architecture:
    OpenWA ──POST/webhook──► Relay ──POST /webhooks/execute/...──► Backend
                 (HMAC)                        (X-API-Key)
"""

import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Request, Response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("openwa-relay")

app = FastAPI(title="openwa-webhook-relay", version="0.1.0")

# ── Config (env vars) ─────────────────────────────────────────

OPENWA_WEBHOOK_SECRET = os.environ.get("OPENWA_WEBHOOK_SECRET", "")
WORKSPACE_ID          = os.environ.get("WORKSPACE_ID", "default")
BACKEND_URL           = os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")
BACKEND_API_KEY       = os.environ.get("BACKEND_API_KEY", "")
TARGET_FLOW           = os.environ.get("TARGET_FLOW", "inbound_lead_flow")
TARGET_MODE           = os.environ.get("TARGET_MODE", "deterministic")


# ── Signature Verification ────────────────────────────────────

def verify_openwa_signature(body: bytes, signature_header: str, secret: str) -> bool:
    """Verify OpenWA HMAC-SHA256 signature (X-OpenWA-Signature header)."""
    if not secret or not signature_header:
        return True  # skip verification when not configured
    try:
        parts = signature_header.split("=", 1)
        if len(parts) != 2 or parts[0] != "sha256":
            return False
        received = parts[1]
        expected = hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, received)
    except Exception:
        return False


# ── Content Builder ───────────────────────────────────────────

def build_content(data: dict) -> str:
    """Extract human-readable content from an OpenWA message.data block."""
    msg_type = data.get("type", "chat")
    body     = data.get("body", "") or ""

    if msg_type == "chat":
        return body

    if msg_type == "image":
        caption = data.get("caption") or data.get("media", {}).get("caption", "")
        return caption or "[Photo]"

    if msg_type == "video":
        caption = data.get("caption") or data.get("media", {}).get("caption", "")
        return caption or "[Video]"

    if msg_type == "audio" or msg_type == "ptt":
        return "[Voice Message]"

    if msg_type == "document":
        filename = data.get("filename") or data.get("media", {}).get("filename", "Unknown")
        caption  = data.get("caption") or data.get("media", {}).get("caption", "")
        text = f"[Document: {filename}]"
        if caption:
            text += f" — {caption}"
        return text

    if msg_type == "sticker":
        return "[Sticker]"

    if msg_type == "location":
        desc = data.get("description", "")
        lat  = data.get("lat", "")
        lng  = data.get("lng", "")
        return f"[Location: {desc or f'{lat},{lng}'}]"

    if msg_type == "vcard" or msg_type == "contact":
        contacts = data.get("vcard", []) if isinstance(data.get("vcard"), list) else []
        names = []
        for c in contacts:
            if isinstance(c, dict):
                names.append(c.get("displayName", "Contact"))
        return f"[Contact: {', '.join(names)}]" if names else "[Contact]"

    return body or f"[{msg_type}]"


def parse_phone(chat_id: str) -> str:
    """5491112345678@c.us → +5491112345678"""
    if "@" in chat_id:
        digits = chat_id.split("@")[0]
        return f"+{digits}"
    return chat_id.strip("+")


# ── Payload Transformer ───────────────────────────────────────

def transform_to_event(
    openwa_payload: dict,
    workspace_id: str,
    session_id: str,
) -> dict:
    """
    OpenWA webhook body → event dict expected by InboundLeadFlow.
    The flow's parse_inbound_message() reads:
      event.payload.content  → message text
      event.source           → channel name
      event.payload.from     → customer phone
      event.payload.profile_name → customer name
    """
    data    = openwa_payload.get("data", {})
    msg_id  = data.get("id", str(uuid.uuid4()))
    msg_from = data.get("from", "")
    msg_type = data.get("type", "chat")
    body     = data.get("body", "") or ""
    contact  = data.get("contact", {}) or {}
    wa_ts    = data.get("waTimestamp", 0)
    has_media = data.get("hasMedia", False)
    is_group  = data.get("isGroup", False)
    group_name = data.get("groupName", "")

    # Media enrichment — OpenWA may include a 'media' sub-object
    media = data.get("media", {}) or {}
    media_url  = media.get("url", "")
    media_mime = media.get("mimetype", "")
    media_caption = media.get("caption", "")
    media_filename = media.get("filename", "")

    payload = {
        "event_type":       "message_received",
        "message_id":       msg_id,
        "from":             msg_from,
        "phone":            parse_phone(msg_from),
        "timestamp":        wa_ts,
        "timestamp_iso":    datetime.fromtimestamp(wa_ts, tz=timezone.utc).isoformat() if wa_ts else "",
        "type":             msg_type,
        "content":          build_content(data),
        "body":             body,
        "has_media":        has_media,
        "is_group":         is_group,
        "group_name":       group_name,
        "profile_name":     contact.get("name") or contact.get("pushName", ""),
        "push_name":        contact.get("pushName", ""),
        "channel":          "whatsapp",
        "session_id":       session_id,
        "workspace_id":     workspace_id,
        "media_url":        media_url,
        "media_mime":       media_mime,
        "media_caption":    media_caption,
        "media_filename":   media_filename,
    }

    # Remove empty/None values
    payload = {k: v for k, v in payload.items() if v is not None}

    return {
        "event": {
            "event_id":  str(uuid.uuid4()),
            "source":    "whatsapp",
            "payload":   payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id":   msg_from,
            "client_id": workspace_id,
        }
    }


# ── Routes ────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Liveness check."""
    return {
        "status":  "ok",
        "service": "openwa-webhook-relay",
        "workspace_id": WORKSPACE_ID,
    }


@app.post("/webhook")
async def webhook(request: Request):
    """
    Receive OpenWA webhook POST.
    Steps: verify signature → parse → transform → forward to backend.
    """
    body = await request.body()

    # 1. Signature verification
    signature = request.headers.get("X-OpenWA-Signature", "")
    if not verify_openwa_signature(body, signature, OPENWA_WEBHOOK_SECRET):
        logger.warning("Invalid webhook signature")
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 2. Parse
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_type = payload.get("event", "")
    session_id = payload.get("sessionId", "")
    delivery_id = request.headers.get("X-OpenWA-Delivery-Id", "")
    idempotency_key = request.headers.get("X-OpenWA-Idempotency-Key", "")
    retry_count = request.headers.get("X-OpenWA-Retry-Count", "0")

    logger.info(
        f"Webhook: event={event_type} session={session_id} "
        f"dlv={delivery_id} retry={retry_count}"
    )

    # 3. Only relay message.received events
    if event_type != "message.received":
        logger.debug(f"Ignoring event type: {event_type}")
        return {"status": "ignored", "event": event_type}

    # 4. Transform
    event_payload = transform_to_event(payload, WORKSPACE_ID, session_id)

    # 5. Forward to backend
    backend_endpoint = f"{BACKEND_URL}/webhooks/execute/{WORKSPACE_ID}"
    headers = {"Content-Type": "application/json"}
    if BACKEND_API_KEY:
        headers["X-API-Key"] = BACKEND_API_KEY

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                backend_endpoint,
                params={"target": TARGET_FLOW, "mode": TARGET_MODE},
                json=event_payload,
                headers=headers,
            )
            resp.raise_for_status()

            logger.info(
                f"Relayed → backend: {resp.status_code} "
                f"msg_id={payload.get('data', {}).get('id')}"
            )
            return {
                "status": "relayed",
                "backend_status": resp.status_code,
                "message_id": payload.get("data", {}).get("id"),
            }

        except httpx.HTTPStatusError as e:
            logger.error(f"Backend rejected: {e.response.status_code} — {e.response.text[:300]}")
            return Response(
                content=json.dumps({"status": "backend_error", "detail": str(e)}),
                status_code=502,
                media_type="application/json",
            )
        except Exception as e:
            logger.error(f"Forward failed: {e}")
            return Response(
                content=json.dumps({"status": "error", "detail": str(e)}),
                status_code=502,
                media_type="application/json",
            )
