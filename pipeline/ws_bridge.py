"""
WhoApp — WebSocket Bridge
Relays Redis pub/sub messages (alerts + live flows) to browser clients
over WebSocket. Also provides a simple HTTP API for initial device state.
"""
import os
import json
import asyncio
import logging
from datetime import datetime, timezone

import redis.asyncio as aioredis
import websockets
from websockets.server import serve

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [WS-BRIDGE] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
WS_PORT   = int(os.getenv("WS_PORT", 8765))

# All currently connected WebSocket clients
CLIENTS: set = set()


async def redis_listener():
    """Subscribe to Redis channels and broadcast to all WS clients."""
    r = await aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe("alerts", "flows:live")
    log.info("Subscribed to Redis channels: alerts, flows:live")

    async for message in pubsub.listen():
        if message["type"] == "message":
            raw = message["data"]
            if CLIENTS:
                payload = json.dumps({
                    "channel": message["channel"],
                    "data": json.loads(raw) if raw else {},
                    "ts": datetime.now(timezone.utc).isoformat(),
                })
                disconnected = set()
                for ws in list(CLIENTS):
                    try:
                        await ws.send(payload)
                    except Exception:
                        disconnected.add(ws)
                CLIENTS.difference_update(disconnected)


async def get_devices(r):
    """Fetch all device snapshots from Redis."""
    keys = await r.keys("device:last_flow:*")
    devices = []
    for key in keys:
        raw = await r.get(key)
        if raw:
            try:
                devices.append(json.loads(raw))
            except Exception:
                pass
    return devices


async def get_recent_alerts(r, limit=50):
    """Fetch recent alerts from the alerts stream."""
    entries = await r.xrevrange("alerts:stream", count=limit)
    alerts = []
    for _, data in entries:
        try:
            alerts.append(json.loads(data.get("data", "{}")))
        except Exception:
            pass
    return alerts


async def ws_handler(websocket):
    """Handle a new WebSocket client connection."""
    CLIENTS.add(websocket)
    log.info("Client connected. Total: %d", len(CLIENTS))
    r = await aioredis.from_url(REDIS_URL, decode_responses=True)

    try:
        # Send initial state on connect
        devices = await get_devices(r)
        alerts = await get_recent_alerts(r)
        await websocket.send(json.dumps({
            "channel": "init",
            "data": {"devices": devices, "recent_alerts": alerts},
            "ts": datetime.now(timezone.utc).isoformat(),
        }))

        # Keep connection alive — client can send pings
        async for message in websocket:
            try:
                msg = json.loads(message)
                if msg.get("type") == "ping":
                    await websocket.send(json.dumps({"channel": "pong"}))
                elif msg.get("type") == "get_devices":
                    devs = await get_devices(r)
                    await websocket.send(json.dumps({"channel": "devices", "data": devs}))
                elif msg.get("type") == "get_alerts":
                    alrts = await get_recent_alerts(r, limit=msg.get("limit", 50))
                    await websocket.send(json.dumps({"channel": "alerts_history", "data": alrts}))
            except Exception as e:
                log.debug("Client message error: %s", e)

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        CLIENTS.discard(websocket)
        await r.aclose()
        log.info("Client disconnected. Total: %d", len(CLIENTS))


async def main():
    log.info("WS Bridge starting on port %d", WS_PORT)
    async with serve(ws_handler, "0.0.0.0", WS_PORT):
        # Run redis listener and WS server concurrently
        await redis_listener()


if __name__ == "__main__":
    asyncio.run(main())
