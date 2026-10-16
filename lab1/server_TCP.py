"""Concurrent, line-based TCP key-value server on port 9001."""

import socketserver
import threading


STORE: dict[str, str] = {}
STORE_LOCK = threading.Lock()


def execute(command: str) -> str:
    """Return exactly one response, preserving spaces in text and values."""
    name, separator, arguments = command.partition(" ")

    if name == "PING" and not separator:
        return "PONG"
    if name == "ECHO" and separator:
        return arguments
    if name == "SET" and separator:
        key, value_separator, value = arguments.partition(" ")
        if key and value_separator and value:
            with STORE_LOCK:
                STORE[key] = value
            return "OK"
    if name == "GET" and separator and arguments and " " not in arguments:
        with STORE_LOCK:
            return STORE.get(arguments, "NOT_FOUND")
    return "ERR"


class CommandHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            # The buffered stream joins split commands and separates batched ones.
            for line in self.rfile:
                if not line.endswith(b"\n"):
                    break  # An incomplete command at EOF is not a protocol line.
                payload = line[:-1]
                if any(byte < 32 or byte > 126 for byte in payload):
                    response = "ERR"
                else:
                    response = execute(payload.decode("ascii"))
                self.wfile.write((response + "\n").encode("ascii"))
        except (ConnectionError, OSError):
            # A disconnected client must not interrupt other connections.
            pass


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    with TCPServer(("0.0.0.0", 9001), CommandHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
