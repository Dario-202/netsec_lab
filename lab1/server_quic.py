import asyncio
import hashlib
from pathlib import Path

from hypercorn.asyncio import serve
from hypercorn.config import Config

MAX_BODY_SIZE = 256 * 1024
DIRECTORY = Path(__file__).resolve().parent


async def app(scope, receive, send):
    # Hypercorn uses the ASGI lifespan protocol to start and stop the app.
    if scope["type"] == "lifespan":
        while True:
            event = await receive()
            if event["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif event["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    if scope["type"] != "http":
        return

    method = scope["method"]
    path = scope["path"]
    http_version = scope["http_version"]  # "1.1", "2", or "3"

    status = 200
    content_type = b"text/plain; charset=utf-8"

    if method == "GET" and path == "/":
        body = b"HTTPS server running\n"

    elif method == "GET" and path == "/proto":
        body = ("HTTP/" + http_version).encode("ascii")

    elif method == "POST" and path == "/hash":
        digest = hashlib.sha256()
        total = 0

        # Each request has its own ASGI coroutine and hashing state,
        # so QUIC streams can be processed concurrently.
        while True:
            event = await receive()
            if event["type"] == "http.disconnect":
                return
            if event["type"] != "http.request":
                continue

            chunk = event.get("body", b"")
            total += len(chunk)
            if total > MAX_BODY_SIZE:
                status = 413
                body = b"Request body too large\n"
                break

            digest.update(chunk)
            if not event.get("more_body", False):
                body = digest.hexdigest().encode("ascii")
                break

    else:
        status = 404
        body = b"Not found\n"

    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", content_type),
            (b"content-length", str(len(body)).encode("ascii")),
        ],
    })
    await send({"type": "http.response.body", "body": body})


def main():
    certfile = DIRECTORY / "server.crt"
    keyfile = DIRECTORY / "server.key"
    if not certfile.is_file() or not keyfile.is_file():
        raise FileNotFoundError("Place server.crt and server.key next to server_http3.py")

    config = Config()
    config.bind = ["0.0.0.0:4433"]       # HTTPS over TCP (HTTP/1.1, HTTP/2)
    config.quic_bind = ["0.0.0.0:4433"]  # HTTP/3 over QUIC/UDP (ALPN h3)
    config.certfile = str(certfile)
    config.keyfile = str(keyfile)
    config.alt_svc_headers = ['h3=":4433"']

    print("HTTPS/TCP and HTTP/3/UDP listening on port 4433", flush=True)
    asyncio.run(serve(app, config))


if __name__ == "__main__":
    main()
