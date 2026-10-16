"""Mini HTTP API. Run with: python server_http.py."""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class APIHandler(BaseHTTPRequestHandler):
    notes: dict[int, str] = {}
    next_id = 1
    lock = threading.Lock()

    def respond(self, status, body=None, allow=None):
        payload = b"" if body is None else json.dumps(body).encode("utf-8")
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def route(self):
        url = urlsplit(self.path)
        path = url.path
        method = self.command

        if path == "/":
            self.respond(200 if method == "GET" else 405,
                         allow=None if method == "GET" else "GET")
            return
        if path == "/echo":
            if method != "GET":
                self.respond(405, allow="GET")
                return
            message = parse_qs(url.query, keep_blank_values=True).get("msg", [""])[0]
            self.respond(200, {"msg": message})
            return
        if path == "/notes":
            if method != "POST":
                self.respond(405, allow="POST")
                return
            if self.headers.get_content_type() != "application/json":
                self.respond(415)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0:
                    raise ValueError("Negative content length")
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict) or not isinstance(data.get("text"), str):
                    raise ValueError("Expected a string text field")
            except (ValueError, UnicodeError):
                self.respond(400)
                return
            with APIHandler.lock:
                note_id = APIHandler.next_id
                APIHandler.next_id += 1
                APIHandler.notes[note_id] = data["text"]
            self.respond(201, {"id": note_id})
            return

        match = re.fullmatch(r"/notes/([0-9]+)", path)
        if match:
            try:
                note_id = int(match.group(1))
            except ValueError:
                self.respond(404)
                return
            with APIHandler.lock:
                if note_id not in APIHandler.notes:
                    status, body = 404, None
                elif method == "GET":
                    status, body = 200, {"id": note_id, "text": APIHandler.notes[note_id]}
                elif method == "DELETE":
                    del APIHandler.notes[note_id]
                    status, body = 204, None
                else:
                    status, body = 405, None
            self.respond(status, body, allow="GET, DELETE" if status == 405 else None)
            return
        self.respond(404)

    do_GET = route
    do_POST = route
    do_DELETE = route
    do_PUT = route
    do_PATCH = route
    do_HEAD = route
    do_OPTIONS = route
    do_TRACE = route
    do_CONNECT = route


def main():
    with ThreadingHTTPServer(("0.0.0.0", 8080), APIHandler) as server:
        print("HTTP server listening on port 8080")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()