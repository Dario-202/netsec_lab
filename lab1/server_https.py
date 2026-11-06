"""HTTPS sessions on 8443 and course-CA client authentication on 8444.

Run with: py lab1/server_https.py
Generate server.crt/server.key first (see README_HTTPS.md).
"""

import json
import secrets
import ssl
import threading
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


DIRECTORY = Path(__file__).resolve().parent
SESSIONS = {}
SESSION_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body=b"", content_type="text/plain; charset=utf-8", cookie=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if self.server.server_port == 8444:
            if path != "/whoami":
                self.respond(404)
                return
            certificate = self.connection.getpeercert()
            common_name = next(
                (value for rdn in certificate.get("subject", ())
                 for key, value in rdn if key == "commonName"), None
            )
            if common_name is None:
                self.respond(400, b"Client certificate has no Common Name")
                return
            self.respond(200, common_name.encode("utf-8"))
        elif path == "/":
            self.respond(200, b"HTTPS server running\n")
        elif path == "/me":
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except CookieError:
                self.respond(401)
                return
            session = cookie.get("session")
            with SESSION_LOCK:
                user = SESSIONS.get(session.value) if session else None
            if user is None:
                self.respond(401)
            else:
                self.respond(200, json.dumps({"user": user}).encode("utf-8"), "application/json")
        else:
            self.respond(404)

    def do_POST(self):
        if self.server.server_port != 8443 or urlsplit(self.path).path != "/login":
            self.respond(404)
            return
        if self.headers.get_content_type() != "application/json":
            self.respond(415)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError
            if self.headers.get("Transfer-Encoding") is not None:
                raise ValueError
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict) or not isinstance(data.get("user"), str):
                raise ValueError
        except (ValueError, UnicodeError):
            self.respond(400)
            return
        if data.get("password") != "netsec":
            self.respond(401)
            return
        token = secrets.token_urlsafe(32)
        with SESSION_LOCK:
            SESSIONS[token] = data["user"]
        self.respond(200, cookie=f"session={token}; Path=/; Secure; HttpOnly; SameSite=Lax")

    def setup(self):
        super().setup()
        self.connection.settimeout(15)


def make_server(port, require_client_certificate=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(DIRECTORY / "server.crt", DIRECTORY / "server.key")
    if require_client_certificate:
        context.load_verify_locations(cafile=DIRECTORY / "ca.crt")
        context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main():
    with make_server(8443) as https, make_server(8444, True) as mtls:
        worker = threading.Thread(target=mtls.serve_forever, daemon=True)
        worker.start()
        print("HTTPS listening on 8443; mTLS listening on 8444", flush=True)
        try:
            https.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            mtls.shutdown()
            worker.join()


if __name__ == "__main__":
    main()
