import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/ws/events", "/ws/jobs", "/activity", "/desktop", "/connection"])
@pytest.mark.parametrize("direction", ["receive", "send"])
@pytest.mark.parametrize("kind,code", [("size", 1009), ("rate", 1013)])
async def test_limits_cover_every_websocket_route(path, direction, kind, code, monkeypatch):
    from backend import request_limits

    monkeypatch.setattr(request_limits, "WS_MESSAGES_PER_SECOND", 2)
    sent = []
    count = 0

    async def receive():
        nonlocal count
        count += 1
        return {"type": "websocket.receive", "text": "x" * (65537 if kind == "size" else 1)}

    async def send(message):
        sent.append(message)

    async def app(scope, incoming, outgoing):
        await outgoing({"type": "websocket.accept"})
        for _ in range(3):
            if direction == "receive":
                await incoming()
            else:
                await outgoing(
                    {"type": "websocket.send", "bytes": b"x" * (65537 if kind == "size" else 1)}
                )

    await request_limits.WebSocketLimits(app)({"type": "websocket", "path": path}, receive, send)
    assert sent[-1]["type"] == "websocket.close" and sent[-1]["code"] == code
    assert len([item for item in sent if item["type"] == "websocket.close"]) == 1


def test_actual_shared_stream_applies_size_limit_and_all_topics(tmp_path):
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from backend.main import create_app

    app = create_app("f" * 64, "stream-limit", tmp_path)
    with TestClient(app) as client:
        for topic in ("activity", "desktop", "connection"):
            with client.websocket_connect(
                "/ws/events", headers={"Authorization": "Bearer " + "f" * 64}
            ) as socket:
                client.portal.call(app.state.events.publish, topic, {"message": "ready"})
                assert socket.receive_json()["topic"] == topic
                socket.send_text("x" * 65537)
                with pytest.raises(WebSocketDisconnect) as error:
                    socket.receive_json()
                assert error.value.code == 1009
