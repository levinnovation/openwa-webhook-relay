# OpenWA Webhook Relay

A small standalone FastAPI service that sits between [OpenWA](https://github.com/rmyndharis/OpenWA) and the `lev-agent-demo` backend to enable **inbound WhatsApp message handling**.

## What This Solves

OpenWA is a self-hosted WhatsApp gateway (built on Baileys) that supports outbound messaging and can be queried for recent messages — but it does **not** emit webhooks for incoming messages out of the box. Without this relay, the system can only **send** WhatsApp messages, not **receive** them.

This relay:
1. Receives OpenWA events (e.g. via OpenWA's internal event log or a sidecar that polls)
2. Verifies the HMAC-SHA256 signature shared with the backend
3. Transforms the OpenWA event into the format expected by the backend's `InboundLeadFlow` (CrewAI Flow: parse → classify → CRM → schedule → respond)
4. Forwards the transformed payload to `POST /webhooks/execute/{workspace_id}?target=inbound_lead_flow` with the backend's API key
5. Returns 200 OK immediately so OpenWA doesn't time out — the actual flow runs in a `BackgroundTasks` worker

## Architecture

```
[customer WhatsApp]
       │
       ▼
[OpenWA Baileys server]    ←── deployed as Railway image (ghcr.io/rmyndharis/openwa)
       │ (OpenWA emits its own internal events, but doesn't have webhooks)
       │
       ▼
[openwa-webhook-relay]      ←── THIS SERVICE
       │ (HMAC-SHA256 signed, async background task)
       │ (transforms OpenWA → InboundLeadFlow format)
       ▼
[Backend /webhooks/execute/{ws}?target=inbound_lead_flow]
       │
       ▼
[InboundLeadFlow]           ←── CrewAI Flow (parse → classify → CRM → schedule → respond)
       │
       ▼
[Backend sends response via OpenWA]
       │
       ▼
[customer receives WhatsApp reply]
```

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/health` | Liveness check; returns workspace_id |
| `POST` | `/webhook` | Receives OpenWA events, verifies HMAC, transforms, forwards |

## Configuration

Set these env vars in Railway:

| Variable | Description |
|----------|-------------|
| `OPENWA_WEBHOOK_SECRET` | Shared secret with the backend (HMAC-SHA256) |
| `WORKSPACE_ID` | The workspace the relay forwards events for |
| `BACKEND_URL` | URL of the lev-agent-demo backend (e.g. `https://apiagentsclientlev-production.up.railway.app`) |
| `BACKEND_API_KEY` | `X-API-Key` for the backend |
| `TARGET_FLOW` | Default: `inbound_lead_flow` |
| `TARGET_MODE` | Default: `deterministic` |

## Payload Transformation

OpenWA emits events in this shape (simplified):

```json
{
  "event": "message.received",
  "sessionId": "22715d7e-8b6e-48e8-99b9-c22a0e7f6869",
  "data": {
    "id": "true_5491112345678@c.us_ABC",
    "from": "5491112345678@c.us",
    "to": "50671440007@c.us",
    "body": "Hola, me interesa el servicio",
    "type": "chat",
    "waTimestamp": 1748793600,
    "hasMedia": false,
    "contact": {"name": "Juan", "pushName": "Juan"}
  }
}
```

The relay transforms it into the format the `InboundLeadFlow.parse_inbound_message` expects:

```json
{
  "event": {
    "event_id": "<uuid>",
    "source": "whatsapp",
    "payload": {
      "event_type": "message_received",
      "from": "5491112345678@c.us",
      "phone": "+5491112345678",
      "type": "chat",
      "content": "Hola, me interesa el servicio",
      "profile_name": "Juan",
      "channel": "whatsapp",
      "timestamp": 1748793600
    },
    "user_id": "5491112345678@c.us",
    "client_id": "<WORKSPACE_ID>"
  }
}
```

It then forwards this to `{BACKEND_URL}/webhooks/execute/{WORKSPACE_ID}?target={TARGET_FLOW}&mode={TARGET_MODE}` as a `POST` with the backend's API key in the `X-API-Key` header.

## Setup

### 1. Deploy the Relay

This service is deployed on Railway as a separate service in the same project as `lev-agent-demo`. The Railway config (`railway.json`) uses Nixpacks auto-detect.

### 2. Configure Webhook in OpenWA

OpenWA doesn't have native webhooks, so the relay expects you to set up a sidecar that:
1. Polls OpenWA's `/api/sessions/{id}/messages` endpoint (or `/api/sessions/{id}/chats/{chatId}/messages` for history)
2. Detects new messages (by comparing to a previously-seen set)
3. POSTs them to `{RELAY_URL}/webhook` with an HMAC-SHA256 signature header

If you don't have such a sidecar yet, you can also have OpenWA's admin dashboard forward events by setting up a custom integration in OpenWA.

### 3. Register Webhook in OpenWA

Use the `register_webhook.py` CLI to register a webhook in OpenWA (or use OpenWA's admin dashboard):

```bash
python register_webhook.py register \
  --openwa-url https://openwa-api-production-6d50.up.railway.app \
  --session-id <OPENWA_SESSION_ID> \
  --api-key <OPENWA_API_KEY> \
  --relay-url https://openwa-webhook-relay-production.up.railway.app/webhook \
  --secret <SHARED_SECRET>
```

### 4. Test

```bash
# Health check
curl https://openwa-webhook-relay-production.up.railway.app/health

# Manual test (with a valid HMAC signature)
python -c "
import hmac, hashlib, json, requests
secret = b'your-secret'
body = json.dumps({'event': 'message.received', 'data': {...}}).encode()
sig = hmac.new(secret, body, hashlib.sha256).hexdigest()
requests.post('https://openwa-webhook-relay-production.up.railway.app/webhook',
              data=body, headers={'Content-Type': 'application/json', 'X-OpenWA-Signature': sig})
"
```

## Testing

23 unit tests cover:

- HMAC-SHA256 signature verification (valid, invalid, missing)
- OpenWA event parsing (text, image, video, audio, document, sticker, location, contact)
- Payload transformation to backend format
- Error handling (network failures, invalid JSON, missing fields)
- Idempotency via `X-OpenWA-Delivery-Id` and `X-OpenWA-Idempotency-Key`
- Backend forwarding with `X-API-Key` header
- Background task execution (returns 200 immediately, processes in background)

Run them with:
```bash
python -m pytest test_main.py -v
```

## Related Services

- **lev-agent-demo** — the backend that receives the transformed events and runs the `InboundLeadFlow`
- **OpenWA API** — the WhatsApp gateway that emits the events
- **agentyx-crew** — the parent workspace containing all three repos

## File Layout

```
openwa-webhook-relay/
├── main.py              # FastAPI app with /webhook and /health endpoints
├── register_webhook.py  # CLI to register webhook in OpenWA via its API
├── test_main.py         # 23 unit tests
├── requirements.txt     # fastapi, httpx, uvicorn
├── Dockerfile
└── railway.json         # Nixpacks config
```
