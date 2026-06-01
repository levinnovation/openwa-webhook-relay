"""
Tests for the OpenWA webhook relay.
Run:  cd openwa-webhook-relay && python -m pytest test_main.py -v
"""

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from main import (
    app,
    build_content,
    parse_phone,
    transform_to_event,
    verify_openwa_signature,
)

client = TestClient(app)

SECRET = "test-secret"


# ── Unit Tests ────────────────────────────────────────────────

def test_verify_signature_valid():
    body = b'{"event":"message.received"}'
    expected = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    sig = f"sha256={expected}"
    assert verify_openwa_signature(body, sig, SECRET) is True


def test_verify_signature_wrong():
    body = b'{"event":"message.received"}'
    assert verify_openwa_signature(body, "sha256=badhash", SECRET) is False


def test_verify_signature_empty():
    assert verify_openwa_signature(b"{}", "", "") is True  # no secret → skip


def test_verify_signature_unexpected_format():
    assert verify_openwa_signature(b"{}", "bearer token", SECRET) is False


def test_parse_phone_chat_id():
    assert parse_phone("5491112345678@c.us") == "+5491112345678"


def test_parse_phone_gid():
    assert parse_phone("5491112345678-111@g.us") == "+5491112345678-111"


def test_parse_phone_plain():
    assert parse_phone("+5491112345678") == "5491112345678"


# ── Content Builder Tests ─────────────────────────────────────

def test_build_content_text():
    assert build_content({"type": "chat", "body": "Hola mundo"}) == "Hola mundo"


def test_build_content_image():
    assert build_content({"type": "image", "caption": "Mira esto"}) == "Mira esto"
    assert build_content({"type": "image"}) == "[Photo]"


def test_build_content_video():
    assert build_content({"type": "video", "caption": "Video!"}) == "Video!"
    assert build_content({"type": "video"}) == "[Video]"


def test_build_content_audio():
    assert build_content({"type": "audio"}) == "[Voice Message]"


def test_build_content_document():
    assert build_content({
        "type": "document",
        "filename": "report.pdf",
        "caption": "Acá está",
    }) == "[Document: report.pdf] — Acá está"


def test_build_content_sticker():
    assert build_content({"type": "sticker"}) == "[Sticker]"


def test_build_content_location():
    assert build_content({"type": "location", "description": "Oficina"}) == "[Location: Oficina]"


def test_build_content_unknown():
    assert build_content({"type": "xyz", "body": "algo"}) == "algo"


# ── Transform Tests ───────────────────────────────────────────

def test_transform_text_message():
    openwa = {
        "event": "message.received",
        "sessionId": "sess_abc",
        "data": {
            "id": "true_5491112345678@c.us_ABC123",
            "from": "5491112345678@c.us",
            "to": "5491198765432@c.us",
            "body": "Hola, quiero info",
            "type": "chat",
            "waTimestamp": 1706868000,
            "hasMedia": False,
            "isGroup": False,
            "contact": {"name": "Juan Pérez", "pushName": "Juan"},
        },
    }

    result = transform_to_event(openwa, "acme-corp", "sess_abc")
    event = result["event"]
    payload = event["payload"]

    assert event["source"] == "whatsapp"
    assert event["client_id"] == "acme-corp"
    assert payload["event_type"] == "message_received"
    assert payload["content"] == "Hola, quiero info"
    assert payload["type"] == "chat"
    assert payload["phone"] == "+5491112345678"
    assert payload["profile_name"] == "Juan Pérez"
    assert payload["channel"] == "whatsapp"
    assert payload["has_media"] is False


def test_transform_media_message():
    openwa = {
        "event": "message.received",
        "sessionId": "sess_abc",
        "data": {
            "id": "true_5491112345678@c.us_XYZ",
            "from": "5491112345678@c.us",
            "type": "image",
            "hasMedia": True,
            "caption": "Foto del producto",
            "media": {
                "url": "https://mmg.whatsapp.net/...",
                "mimetype": "image/jpeg",
            },
            "waTimestamp": 1706868000,
            "contact": {"pushName": "Maria"},
        },
    }

    result = transform_to_event(openwa, "acme-corp", "sess_abc")
    payload = result["event"]["payload"]

    assert payload["content"] == "Foto del producto"
    assert payload["type"] == "image"
    assert payload["has_media"] is True
    assert payload["media_url"] == "https://mmg.whatsapp.net/..."
    assert payload["media_mime"] == "image/jpeg"


def test_transform_group_message():
    openwa = {
        "event": "message.received",
        "sessionId": "sess_abc",
        "data": {
            "id": "true_111@g.us_GRP",
            "from": "111@g.us",
            "body": "Alguien?",
            "type": "chat",
            "isGroup": True,
            "groupName": "Soporte Tech",
            "waTimestamp": 1706868000,
            "contact": {},
        },
    }

    result = transform_to_event(openwa, "acme-corp", "sess_abc")
    payload = result["event"]["payload"]

    assert payload["is_group"] is True
    assert payload["group_name"] == "Soporte Tech"


# ── Integration Tests ─────────────────────────────────────────

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "openwa-webhook-relay"


def test_webhook_ignores_non_message_events():
    body = {
        "event": "session.connected",
        "sessionId": "sess_abc",
        "data": {},
    }
    response = client.post("/webhook", json=body)
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


def test_webhook_invalid_json():
    response = client.post(
        "/webhook",
        content="not json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


def test_webhook_integration(monkeypatch):
    """Full integration: receive OpenWA webhook → transform → forward to backend."""
    import main

    monkeypatch.setattr(main, "OPENWA_WEBHOOK_SECRET", "")
    monkeypatch.setattr(main, "WORKSPACE_ID", "test-ws")
    monkeypatch.setattr(main, "BACKEND_API_KEY", "sk-test")

    # Simulate what the backend would receive by mocking httpx
    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            pass

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            pass
        async def post(self, url, params=None, json=None, headers=None):
            # Verify correct forwarding
            assert "webhooks/execute/test-ws" in url
            assert params["target"] == "inbound_lead_flow"
            assert params["mode"] == "deterministic"
            assert json["event"]["source"] == "whatsapp"
            assert json["event"]["payload"]["content"] == "Hola"
            return FakeResponse()

    monkeypatch.setattr(main.httpx, "AsyncClient", FakeAsyncClient)

    openwa_payload = {
        "event": "message.received",
        "sessionId": "sess_abc",
        "data": {
            "id": "true_5491112345678@c.us_ABC",
            "from": "5491112345678@c.us",
            "body": "Hola",
            "type": "chat",
            "waTimestamp": 1706868000,
            "hasMedia": False,
            "isGroup": False,
            "contact": {"name": "Juan", "pushName": "Juan"},
        },
    }

    response = client.post("/webhook", json=openwa_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "relayed"


# ── Payload Golden Test (matching what the backend expects) ────

def test_payload_shape_matches_flow_parser():
    """Ensure the transformed payload is parseable by InboundLeadFlow.parse_inbound_message()."""
    openwa = {
        "event": "message.received",
        "sessionId": "sess_abc",
        "data": {
            "id": "true_5491112345678@c.us_ABC123",
            "from": "5491112345678@c.us",
            "body": "Necesito ayuda con mi factura",
            "type": "chat",
            "waTimestamp": 1706868000,
            "hasMedia": False,
            "isGroup": False,
            "contact": {"name": "Ana López", "pushName": "Ana"},
        },
    }

    result = transform_to_event(openwa, "test-ws", "sess_abc")

    # Simulate what the flow does:
    event    = result["event"]
    payload  = event.get("payload", {})

    text           = payload.get("content", payload.get("message", payload.get("body", "")))
    channel        = payload.get("channel", event.get("source", "unknown"))
    customer_phone = payload.get("from", payload.get("phone", payload.get("sender_phone", "")))
    customer_name  = payload.get("profile_name", payload.get("name", payload.get("sender_name", "Unknown")))

    assert text           == "Necesito ayuda con mi factura"
    assert channel        == "whatsapp"
    assert customer_phone == "5491112345678@c.us"
    assert customer_name  == "Ana López"

    print("\n[ Golden test passed — payload matches InboundLeadFlow expectations ]")
    print(json.dumps(result, indent=2, ensure_ascii=False))
