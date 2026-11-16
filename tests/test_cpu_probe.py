import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError

from phicortex.cpu_probe import (ALIAS, clean_server_env, cpu_command,
                                  report_summary, run_probe, stop_process,
                                  transport_for, validate_local_assets)


class FakeResponse:
    status = 200
    def __init__(self, data):
        self.data = json.dumps(data).encode()
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def read(self, limit=10000000):
        return self.data[:limit]


class FakeOpener:
    def __init__(self, answer="4"):
        self.answer = answer
        self.requests = []
    def open(self, request, timeout=None):
        self.requests.append(request)
        if request.full_url.endswith('/health'):
            return FakeResponse({"status": "ok"})
        return FakeResponse({"choices": [{"message": {"role": "assistant", "content": self.answer}, "finish_reason": "stop"}],
                             "usage": {"prompt_tokens": 9, "completion_tokens": 1}})


class FakeProcess:
    returncode = None
    def __init__(self):
        self.terminated = False
        self.killed = False
    def poll(self):
        return None if not self.terminated else 0
    def terminate(self):
        self.terminated = True
    def wait(self, timeout):
        return 0
    def kill(self):
        self.killed = True
        self.terminated = True


class ProbeTests(unittest.TestCase):
    def test_command_requires_explicit_cpu_and_offline_controls(self):
        cmd = cpu_command(Path("/tmp/llama-server"), Path("/tmp/model.gguf"), 19000, 4, 2048, "hidden-key", 64)
        self.assertEqual(cmd[cmd.index('--n-gpu-layers') + 1], '0')
        self.assertEqual(cmd[cmd.index('--device') + 1], 'none')
        self.assertIn('--offline', cmd)
        self.assertIn('--no-webui', cmd)
        self.assertEqual(cmd[cmd.index('--host') + 1], '127.0.0.1')
        self.assertEqual(cmd[cmd.index('--api-key') + 1], 'hidden-key')

    def test_overrides_from_environment_removed(self):
        with mock.patch.dict(os.environ, {"LLAMA_ARG_N_GPU_LAYERS": "100", "LLAMA_ARG_HOST": "0.0.0.0"}):
            env = clean_server_env()
        self.assertNotIn("LLAMA_ARG_N_GPU_LAYERS", env)
        self.assertNotIn("LLAMA_ARG_HOST", env)
        self.assertEqual(env["CUDA_VISIBLE_DEVICES"], "-1")

    def test_invalid_paths_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / 'server'
            b = Path(tmp) / 'model.gguf'
            a.write_text('fake')
            b.write_bytes(b'fake-model-bits' * 10)
            validate_local_assets(a, b)
            with self.assertRaises(ValueError):
                validate_local_assets(a, Path(tmp)/'missing.gguf')
            with self.assertRaises(ValueError):
                cpu_command(a, b, 0, 4, 2048, 'key', 64)

    def test_transport_never_sends_to_remote_urls(self):
        opener = FakeOpener()
        send = transport_for(opener, 18943, 'secret', 24)
        data = send(None, {'model': ALIAS, 'messages': [{'role': 'user', 'content': 'hi'}]})
        self.assertEqual(data['choices'][0]['message']['content'], '4')
        self.assertEqual(opener.requests[0].full_url, 'http://127.0.0.1:18943/v1/chat/completions')
        self.assertEqual(json.loads(opener.requests[0].data)['max_tokens'], 24)

    def test_complete_mock_run_omits_secret_and_cannot_promote_router(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = Path(tmp)/'llama-server.exe'
            model = Path(tmp)/'model.gguf'
            out = Path(tmp)/'report.json'
            server.write_bytes(b'fake-server')
            model.write_bytes(b'fake-gguf-model' * 10)
            fake_process = FakeProcess()
            calls = []
            def launch(args, **kwargs):
                calls.append((args, kwargs))
                return fake_process
            with mock.patch('phicortex.cpu_probe.is_port_in_use', return_value=False):
                result = run_probe(server=server, model=model, cases=[
                    {'id': '2+2', 'prompt': '2+2 = ?', 'expected': '4'}],
                    output=out, opener=FakeOpener(), launch=launch, port=18943)
            saved = json.loads(out.read_text())
            self.assertEqual(saved['summary']['cases_passed'], 1)
            self.assertFalse(saved['controls']['gpu_activity_independently_verified'])
            self.assertFalse(saved['controls']['router_policy_promoted'])
            self.assertTrue(saved['controls']['no_gpu_layers_configured'])
            self.assertNotIn(calls[0][0][-1], out.read_text())
            self.assertTrue(fake_process.terminated)
            self.assertTrue(calls[0][1]['shell'] is False)

    def test_process_shutdown_after_failed_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = Path(tmp)/'llama-server'
            model = Path(tmp)/'model.gguf'
            server.write_text('fake-server')
            model.write_bytes(b'fake-gguf-model' * 10)
            process = FakeProcess()
            bad = FakeOpener()
            def broken(*args, **kwargs):
                raise RuntimeError('startup aborted')
            with mock.patch('phicortex.cpu_probe.is_port_in_use', return_value=False), \
                 mock.patch('phicortex.cpu_probe.wait_until_ready', side_effect=broken):
                with self.assertRaises(RuntimeError):
                    run_probe(server=server, model=model, cases=[
                        {'id': 'one', 'prompt': 'hi', 'expected': 'hi'}],
                        output=Path(tmp)/'report.json', opener=bad, launch=lambda *a, **kw: process)
            self.assertTrue(process.terminated)


if __name__ == '__main__':
    unittest.main()
