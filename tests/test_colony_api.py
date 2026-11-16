import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from phicortex.core import Config, Cortex
from phicortex.server import make_handler


class BrainColonyHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        config = Config(chat_model="chat:1", code_model="coder:1", reason_model="reason:1",
                        db_path=os.path.join(self.temp.name, "events.db"))
        self.cortex = Cortex(config, transport=lambda cfg, payload: {
            "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "model": payload["model"], "usage": {"completion_tokens": 2}})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.cortex))
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join()
        self.cortex.close()
        self.temp.cleanup()

    def request(self, path, data=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            method = "POST" if data is not None else "GET"
            connection.request(method, path, None if data is None else json.dumps(data),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_registered_roles_reported_without_unproven_claims(self):
        code, registry = self.request("/v1/colony")
        self.assertEqual(code, 200)
        self.assertEqual({x["role"] for x in registry["roles"]}, {"chat", "code", "reason"})
        self.assertFalse(registry["cpu_only_verified"])
        self.assertEqual(registry["adaptive_policy"], "not_implemented")
        code, available = self.request("/v1/models")
        self.assertEqual(code, 200)
        self.assertIn("reason:1", {x["id"] for x in available["data"]})

    def test_runtime_metadata_is_not_a_quality_score(self):
        code, _ = self.request("/v1/chat/completions", {
            "model": "phicortex-auto",
            "messages": [{"role": "user", "content": "hello private detail"}]})
        self.assertEqual(code, 200)
        code, metrics = self.request("/v1/telemetry")
        self.assertEqual(code, 200)
        self.assertEqual(metrics["models"]["chat:1"]["completed"], 1)
        self.assertEqual(metrics["models"]["chat:1"]["reported_output_tokens"], 2)
        self.assertEqual(metrics["routes"]["default-chat"], 1)
        self.assertEqual(metrics["quality_scores"], "not_measured")
        self.assertNotIn("private detail", json.dumps(metrics))


if __name__ == "__main__":
    unittest.main()
