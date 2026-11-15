import os
import tempfile
import unittest
from phicortex.core import Config, Cortex, RequestError, route


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.config = Config(chat_model="chat", code_model="coder")

    def test_routes_code(self):
        self.assertEqual(route([{"role": "user", "content": "debug this Python function"}], "phicortex-auto", self.config),
                         ("coder", "deterministic-code-keyword"))

    def test_default_chat(self):
        self.assertEqual(route([{"role": "user", "content": "hello"}], None, self.config)[0], "chat")

    def test_rejects_unregistered_model(self):
        with self.assertRaises(RequestError):
            route([{"role": "user", "content": "hi"}], "untrusted", self.config)

    def test_explicit_non_chat_modes_not_misrepresented(self):
        for mode in ("/build", "/test", "/dream"):
            with self.assertRaises(RequestError) as ctx:
                route([{"role": "user", "content": mode}], None, self.config)
            self.assertEqual(ctx.exception.status, 501)

    def test_no_image_support_claim(self):
        with self.assertRaises(RequestError):
            route([{"role": "user", "content": [{"type": "image_url"}]}], None, self.config)


class LedgerTests(unittest.TestCase):
    def test_persists_without_leaking_transcripts_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "events.db")
            config = Config(chat_model="chat", code_model="coder", db_path=path)
            cortex = Cortex(config, transport=lambda cfg, p: {"choices": [{"message": {"content": "pong"}}]})
            result = cortex.chat({"messages": [{"role": "user", "content": "my private words"}]})
            self.assertEqual(result["choices"][0]["message"]["content"], "pong")
            self.assertEqual(cortex.ledger.count(), 1)
            cortex.ledger.close()
            import sqlite3
            with sqlite3.connect(path) as conn:
                raw = conn.execute("SELECT detail FROM events").fetchone()[0]
            self.assertNotIn("my private words", raw)
            self.assertNotIn("pong", raw)
            reopened = Cortex(config)
            self.assertEqual(reopened.ledger.count(), 1)
            reopened.ledger.close()

    def test_no_streaming_pretense(self):
        with tempfile.TemporaryDirectory() as directory:
            cortex = Cortex(Config(db_path=os.path.join(directory,"a.db")), transport=lambda cfg,p: {})
            with self.assertRaises(RequestError):
                cortex.chat({"messages": [{"role":"user", "content":"hi"}], "stream":True})
            cortex.ledger.close()


if __name__ == "__main__":
    unittest.main()
