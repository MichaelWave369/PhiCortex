import os
import tempfile
import unittest

from phicortex.core import Config, Cortex, route, RequestError
from phicortex.colony import choose, overview, registry, RoutingError
from phicortex.evaluate import validated_cases, run_suite


def user(message):
    return [{"role": "user", "content": message}]


class RegistryRoutingTests(unittest.TestCase):
    def test_optional_reason_role_and_explainable_route(self):
        config = Config(chat_model="chat:1", code_model="coder:1", reason_model="reason:1")
        decision = choose(user("compare architectures for reliability"), None, config)
        self.assertEqual((decision.model, decision.role, decision.task_class),
                         ("reason:1", "reason", "reason"))
        self.assertEqual(decision.policy_version, "deterministic-v3-mode-advisory")
        self.assertEqual(route(user("debug Python"), None, config),
                         ("coder:1", "deterministic-code-keyword"))

    def test_unconfigured_reason_falls_back_to_chat(self):
        decision = choose(user("evaluate tradeoffs"), "phicortex-auto",
                          Config(chat_model="chat:1", code_model="code:1"))
        self.assertEqual(decision.model, "chat:1")
        self.assertIn("fallback", decision.reason)

    def test_unregistered_and_invalid_names_rejected(self):
        config = Config(chat_model="chat", code_model="coder")
        with self.assertRaises(RoutingError):
            choose(user("hello"), "external-provider", config)
        with self.assertRaises(RoutingError):
            registry(Config(chat_model="http://bad.example", code_model="coder"))
        with self.assertRaises(RequestError):
            route(user("hello"), "external-provider", config)

    def test_explicit_registered_model(self):
        d = choose(user("hello"), "coder", Config(chat_model="chat", code_model="coder"))
        self.assertEqual(d.reason, "explicit-registered-model")
        self.assertEqual(d.task_class, "chat")

    def test_registry_does_not_claim_quality_or_gpu_verification(self):
        info = overview(Config())
        self.assertFalse(info["cpu_only_verified"])
        self.assertEqual(info["backend_readiness"], "not_probed")
        self.assertTrue(all(not x["quality_evaluated"] for x in info["roles"]))


class EvaluationTests(unittest.TestCase):
    def test_known_answer_scoring_and_no_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(chat_model="weak", code_model="strong",
                            db_path=os.path.join(directory, "events.db"))
            def fake_transport(cfg, payload):
                answer = "4" if payload["model"] == "strong" else "five"
                return {"choices": [{"message": {"role": "assistant", "content": answer}}],
                        "usage": {"prompt_tokens": 11, "completion_tokens": 1}}
            cortex = Cortex(config, transport=fake_transport)
            try:
                report = run_suite(cortex, [
                    {"id": "two-plus-two", "prompt": "2+2? Respond with a number.", "expected": "4"}
                ], ["weak", "strong"])
                self.assertEqual([r["pass_rate"] for r in report["results"]], [0, 1])
                self.assertFalse(report["cpu_only_verified"])
                self.assertTrue(report["no_routing_or_weight_changes_applied"])
                self.assertEqual(cortex.ledger.count(), 2)
                self.assertEqual(report["results"][1]["cases"][0]["usage"]["prompt_tokens"], 11)
            finally:
                cortex.close()

    def test_validation_rejects_invalid_or_unscorable_cases(self):
        with self.assertRaises(ValueError):
            validated_cases([{"id": "a", "prompt": "hello", "expected": ""}])
        with self.assertRaises(ValueError):
            validated_cases([{"id": "a", "prompt": "ok", "expected": "yes"},
                             {"id": "a", "prompt": "ok", "expected": "yes"}])

    def test_backend_failure_does_not_create_false_success(self):
        with tempfile.TemporaryDirectory() as directory:
            cortex = Cortex(Config(chat_model="one", code_model="two",
                                   db_path=os.path.join(directory, "events.db")),
                            transport=lambda cfg, req: {"choices": []})
            try:
                report = run_suite(cortex, [{"id": "a", "prompt": "hi", "expected": "yes"}], ["one"])
                case = report["results"][0]["cases"][0]
                self.assertFalse(case["passed"])
                self.assertEqual(case["error_type"], "IndexError")
            finally:
                cortex.close()

    def test_unregistered_model_cannot_be_evaluated(self):
        with tempfile.TemporaryDirectory() as directory:
            cortex = Cortex(Config(db_path=os.path.join(directory, "db.sqlite3")),
                            transport=lambda cfg, req: {})
            try:
                with self.assertRaises(ValueError):
                    run_suite(cortex, [{"id": "a", "prompt": "hi", "expected": "ok"}], ["remote"])
            finally:
                cortex.close()


if __name__ == "__main__":
    unittest.main()
