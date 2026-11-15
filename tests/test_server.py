import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from phicortex.core import Config, Cortex
from phicortex.server import make_handler


class APITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cortex = Cortex(Config(chat_model="chat", code_model="coder", db_path=os.path.join(self.tmp.name,"db.sqlite3")),
                             transport=lambda cfg,p: {"id":"test", "object":"chat.completion", "model":p["model"],
                                                      "choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]})
        self.server = ThreadingHTTPServer(("127.0.0.1",0), make_handler(self.cortex))
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.cortex.ledger.close()
        self.tmp.cleanup()

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        conn.request(method, path, json.dumps(body) if body is not None else None,
                     {"Content-Type":"application/json"})
        response = conn.getresponse()
        data = json.loads(response.read())
        status = response.status
        conn.close()
        return status, data

    def test_chat_and_health(self):
        status, result = self.request("POST", "/v1/chat/completions", {"model":"phicortex-auto", "messages":[{"role":"user", "content":"hello"}]})
        self.assertEqual(status,200)
        self.assertEqual(result["model"],"chat")
        status, health = self.request("GET","/health")
        self.assertEqual(status,200)
        self.assertEqual(health["events"],1)

    def test_unimplemented_mode(self):
        status, _ = self.request("POST", "/v1/chat/completions", {"messages":[{"role":"user", "content":"/dream"}]})
        self.assertEqual(status,501)

    def test_streaming_rejected(self):
        status, _ = self.request("POST", "/v1/chat/completions", {"messages":[{"role":"user", "content":"hi"}],"stream":True})
        self.assertEqual(status,400)

    def test_unknown_path(self):
        status, _ = self.request("GET", "/not-real")
        self.assertEqual(status,404)


if __name__ == "__main__":
    unittest.main()
