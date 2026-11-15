"""Loopback-only OpenAI-style HTTP interface with intentionally limited phase-1 scope."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .core import Config, Cortex, RequestError

MAX_REQUEST = 1_048_576


def make_handler(cortex: Cortex):
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status: int, data: dict) -> None:
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self.respond(200, {"status": "ok", "phase": 1, "events": cortex.ledger.count(), "cpu_first": True})
            elif self.path == "/v1/models":
                models = sorted({cortex.config.chat_model, cortex.config.code_model})
                self.respond(200, {"object": "list", "data": [{"id": "phicortex-auto", "object": "model"}] + [
                    {"id": m, "object": "model"} for m in models]})
            else:
                self.respond(404, {"error": {"message": "not found"}})

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.respond(404, {"error": {"message": "not found"}})
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size < 1 or size > MAX_REQUEST:
                    raise RequestError("invalid or oversized request")
                request = json.loads(self.rfile.read(size))
                response = cortex.chat(request)
                self.respond(200, response)
            except (ValueError, json.JSONDecodeError) as exc:
                self.respond(400, {"error": {"message": str(exc)}})
            except RequestError as exc:
                self.respond(exc.status, {"error": {"message": str(exc)}})

    return Handler


def run() -> None:
    config = Config.from_env()
    cortex = Cortex(config)
    server = ThreadingHTTPServer(("127.0.0.1", 8765), make_handler(cortex))
    try:
        print("PhiCortex phase 1 listening on http://127.0.0.1:8765", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        cortex.ledger.close()
