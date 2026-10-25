import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs


class APIHandler(BaseHTTPRequestHandler):
    notes = {}
    next_id = 1

    def respond(self, status, body=None, allow=None):
        data = json.dumps(body).encode("utf-8") if body is not None else b""

        self.send_response(status)

        if body is not None:
            self.send_header("Content-Type", "application/json")

        self.send_header("Content-Length", str(len(data)))

        if allow:
            self.send_header("Allow", allow)

        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(data)

    def route(self):
        url = urlsplit(self.path)
        path = url.path
        method = self.command

        # GET /
        if path == "/":
            if method == "GET":
                self.respond(200)
            else:
                self.respond(405, allow="GET")
            return

        # GET /echo?msg=...
        if path == "/echo":
            if method != "GET":
                self.respond(405, allow="GET")
                return

            message = parse_qs(
                url.query, keep_blank_values=True
            ).get("msg", [""])[0]

            self.respond(200, {"msg": message})
            return

        # POST /notes
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
                    raise ValueError

                data = json.loads(self.rfile.read(length))

                if not isinstance(data, dict) or not isinstance(data.get("text"), str):
                    raise ValueError

            except (ValueError, UnicodeError):
                self.respond(400)
                return

            note_id = APIHandler.next_id
            APIHandler.next_id += 1
            APIHandler.notes[note_id] = data["text"]

            self.respond(201, {"id": note_id})
            return

        # GET /notes/<id> and DELETE /notes/<id>
        match = re.fullmatch(r"/notes/([0-9]+)", path)

        if match:
            try:
                note_id = int(match.group(1))
            except ValueError:
                self.respond(404)
                return

            if note_id not in APIHandler.notes:
                self.respond(404)
                return

            if method == "GET":
                self.respond(200, {
                    "id": note_id,
                    "text": APIHandler.notes[note_id]
                })

            elif method == "DELETE":
                del APIHandler.notes[note_id]
                self.respond(204)

            else:
                self.respond(405, allow="GET, DELETE")

            return

        # Unknown path
        self.respond(404)

    do_GET = do_POST = do_DELETE = route
    do_PUT = do_PATCH = do_HEAD = do_OPTIONS = do_TRACE = do_CONNECT = route


def main():
    with HTTPServer(("0.0.0.0", 8080), APIHandler) as server:
        print("HTTP server listening on port 8080")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
