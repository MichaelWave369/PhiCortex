"""LATTICE request-scoped advisory mode routing regression tests.

Modes only select registered local inference roles. They cannot create
jobs, start workers, expand permissions, or change the model's tool access.
"""
import http.client
import json
import os
import sqlite3
from contextlib import closing
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from phicortex.colony import choose, RoutingError, overview
from phicortex.core import Config, Cortex, route, RequestError
from phicortex.server import make_handler


def user(text):
    return [{"role": "user", "content": text}]


class ModeRouterTests(unittest.TestCase):
    def setUp(self):
        self.config = Config(chat_model="local-chat", code_model="local-code",
                             reason_model="local-reason")

    def test_four_explicit_modes_are_advisory(self):
        routes = {
            "chat": ("local-chat", "chat", "operator-chat"),
            "dream": ("local-reason", "reason", "operator-dream-advisory-reason"),
            "build": ("local-code", "code", "operator-build-advisory-code"),
            "test": ("local-code", "code", "operator-test-advisory-code"),
        }
        for mode, expected in routes.items():
            with self.subTest(mode=mode):
                selected = choose(user("a generic neutral message"), None,
                                  self.config, mode=mode)
                self.assertEqual((selected.model, selected.role, selected.reason), expected)
                self.assertEqual(selected.mode, mode)
                self.assertEqual(selected.mode_source, "operator-request")
                self.assertFalse(selected.execution_authorized)

    def test_no_mode_keeps_legacy_keyword_routing(self):
        self.assertEqual(route(user("debug Python"), None, self.config),
                         ("local-code", "deterministic-code-keyword"))
        self.assertEqual(route(user("compare architectures"), None, self.config),
                         ("local-reason", "deterministic-reason-keyword"))
        self.assertEqual(route(user("hi"), None, self.config),
                         ("local-chat", "default-chat"))
        self.assertEqual(choose(user("debug Python"), None, self.config).mode_source, "default")

    def test_explicit_chat_overrides_code_keyword(self):
        chosen = choose(user("write code in Python"), None,
                        self.config, mode="chat")
        self.assertEqual(chosen.model, "local-chat")
        self.assertEqual(chosen.reason, "operator-chat")

    def test_dream_missing_reason_falls_back_to_chat(self):
        cfg = Config(chat_model="chat", code_model="code")
        selected = choose(user("a harmless idea"), None, cfg, mode="dream")
        self.assertEqual(selected.model, "chat")
        self.assertIn("fallback", selected.reason)

    def test_explicit_registered_model_still_allowlisted(self):
        chosen = choose(user("hello"), "local-chat", self.config, mode="test")
        self.assertEqual(chosen.reason, "explicit-registered-model")
        self.assertEqual(chosen.model, "local-chat")
        self.assertFalse(chosen.execution_authorized)
        with self.assertRaises(RoutingError):
            choose(user("hello"), "external:unknown", self.config, mode="test")

    def test_invalid_modes_fail_closed(self):
        for mode in ("execute", "deploy", "Build", "", 17, False, [], {}):
            with self.subTest(mode=mode), self.assertRaises(RoutingError):
                choose(user("hi"), None, self.config, mode=mode)

    def test_old_slash_commands_are_not_worker_triggers(self):
        for slash in ("/build", "/test", "/dream"):
            with self.assertRaises(RequestError) as ctx:
                route(user(slash), None, self.config, mode="build")
            self.assertEqual(ctx.exception.status, 501)

    def test_colony_overview_denies_capability_escalation(self):
        info = overview(self.config)
        self.assertEqual(info["request_modes"], ["chat", "dream", "build", "test"])
        self.assertEqual(info["mode_authority"], "advisory_inference_only")
        self.assertEqual(info["persistent_mode_state_machine"], "not_implemented")
        self.assertEqual(info["adaptive_policy"], "not_implemented")


class ModeHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = os.path.join(self.tmp.name, "ledger.sqlite3")
        self.sent = []
        def transport(cfg, payload):
            self.sent.append(payload)
            return {"model": payload["model"],
                    "choices": [{"message": {"role": "assistant", "content": "ok"},
                                 "finish_reason": "stop"}]}
        self.cortex = Cortex(Config(chat_model="local-chat",
                                    code_model="local-code",
                                    reason_model="local-reason",
                                    db_path=self.database), transport=transport)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.cortex))
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join()
        self.cortex.close()
        self.tmp.cleanup()

    def http(self, data):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=3)
        try:
            c.request("POST", "/v1/chat/completions", body=json.dumps(data),
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read())
        finally:
            c.close()

    def test_build_test_dream_only_choose_models(self):
        for mode, model in (("build", "local-code"),
                            ("test", "local-code"),
                            ("dream", "local-reason")):
            with self.subTest(mode=mode):
                status, reply = self.http({
                    "mode": mode, "model": "phicortex-auto",
                    "messages": user("Plan a safe hypothetical scenario")})
                self.assertEqual(status, 200)
                self.assertEqual(reply["model"], model)
        self.assertEqual([p["model"] for p in self.sent],
                         ["local-code", "local-code", "local-reason"])
        for payload in self.sent:
            self.assertEqual(set(payload), {"model", "messages", "stream"})
        with closing(sqlite3.connect(self.database)) as db:
            rows = [json.loads(x[0]) for x in db.execute(
                "SELECT detail FROM events ORDER BY id")]
        self.assertEqual([r["mode"] for r in rows], ["build", "test", "dream"])
        self.assertTrue(all(r["mode_source"] == "operator-request" for r in rows))
        self.assertTrue(all(r["execution_authorized"] is False for r in rows))
        self.assertTrue(all("Plan a safe hypothetical scenario" not in json.dumps(r)
                            for r in rows))

    def test_invalid_mode_rejected_before_inference(self):
        for mode in ("execute", "", None, 9, {}):
            with self.subTest(mode=mode):
                status, body = self.http({"mode": mode, "messages": user("hi")})
                self.assertEqual(status, 400)
        self.assertEqual(self.sent, [])

    def test_no_mode_remains_chat_and_logs_default(self):
        status, reply = self.http({"messages": user("hello")})
        self.assertEqual(status, 200)
        self.assertEqual(reply["model"], "local-chat")
        with closing(sqlite3.connect(self.database)) as db:
            row = json.loads(db.execute("SELECT detail FROM events").fetchone()[0])
        self.assertEqual(row["mode"], "chat")
        self.assertEqual(row["mode_source"], "default")
        self.assertFalse(row["execution_authorized"])

    def test_chat_response_not_exposed_to_notes_store(self):
        status, _ = self.http({"messages": user("untrusted project note markdown")})
        self.assertEqual(status, 200)
        # Project notes are a separate, manually invoked local store.
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "notes.sqlite3")))


if __name__ == "__main__":
    unittest.main()
