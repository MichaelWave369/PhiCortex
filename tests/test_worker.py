import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from phicortex.worker import (WorkerError, plan, execute, require_runsc,
                              validate_workspace, MAX_OUTPUT_BYTES)


IMAGE = "python:3.12-alpine@sha256:" + "a" * 64


class WorkerPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "project"
        self.workspace.mkdir()
        (self.workspace / "hello.py").write_text("print(42)\n")

    def job(self, mode="test"):
        return plan(mode, self.root, self.workspace, IMAGE, 10, platform_name="Linux")

    def test_default_is_a_fixed_offline_gvisor_container(self):
        cmd = self.job()["argv"]
        for flag in ("--runtime=runsc", "--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--pull=never",
                     "--user=65534:65534", "--pids-limit=64", "--memory=512m",
                     "--cpus=1"):
            self.assertIn(flag, cmd)
        self.assertIn("--mount=type=bind,source=" + str(self.workspace.resolve()) + ",target=/workspace,readonly", cmd)
        self.assertEqual(cmd[-8:], ["python", "-B", "-m", "unittest", "discover", "-s", "tests", "-v"])

    def test_build_check_is_syntax_only_and_does_not_run_shell(self):
        job = self.job("build-check")
        self.assertEqual(job["build_meaning"], "syntax-only")
        self.assertIn("ast.parse", job["argv"][-1])
        self.assertNotIn("sh", job["argv"][-2:])
        self.assertFalse(job["host_code_execution"])

    def test_refuses_unpinned_and_remote_images(self):
        for image in ("python:latest", "img@sha256:bad", "https://bad.example",
                      "img@sha256:" + "F" * 64):
            with self.assertRaises(WorkerError):
                plan("test", self.root, self.workspace, image, platform_name="Linux")

    def test_refuses_outside_root_and_symlinks(self):
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(WorkerError):
                validate_workspace(self.root, Path(other))
        link = self.workspace / "escape"
        try:
            link.symlink_to(self.root)
        except OSError:
            self.skipTest("symlinks unavailable on this runner")
        with self.assertRaises(WorkerError):
            self.job()

    def test_refuses_docker_mount_option_separators_in_workspace(self):
        tricky = self.root / "comma,readonly=false"
        tricky.mkdir()
        with self.assertRaises(WorkerError):
            plan("test", self.root, tricky, IMAGE, platform_name="Linux")

    def test_refuses_unapproved_modes_and_native_windows(self):
        with self.assertRaises(WorkerError):
            plan("shell", self.root, self.workspace, IMAGE, platform_name="Linux")
        with self.assertRaises(WorkerError):
            plan("test", self.root, self.workspace, IMAGE, platform_name="Windows")

    def test_runtime_refuses_remote_daemon_and_unregistered_gvisor(self):
        with mock.patch("phicortex.worker._docker_capture",
                        side_effect=["tcp://127.0.0.1:2375"]):
            with self.assertRaises(WorkerError):
                require_runsc()
        with mock.patch("phicortex.worker._docker_capture",
                        side_effect=["unix:///var/run/docker.sock", "linux", '{"runc":{}}']):
            with self.assertRaises(WorkerError):
                require_runsc()
        with mock.patch("phicortex.worker._docker_capture",
                        side_effect=["unix:///var/run/docker.sock", "linux", '{"runc":{},"runsc":{}}']):
            require_runsc()

    def test_incomplete_job_plan_never_launches(self):
        job = self.job()
        job["argv"].remove("--network=none")
        launch = mock.Mock()
        with mock.patch("phicortex.worker.platform.system", return_value="Linux"):
            with self.assertRaises(WorkerError):
                execute(job, guard=lambda: None, launch=launch)
        launch.assert_not_called()

    def test_tampered_docker_privilege_flag_never_launches(self):
        job = self.job()
        job["argv"].insert(5, "--privileged")
        launch = mock.Mock()
        with mock.patch("phicortex.worker.platform.system", return_value="Linux"):
            with self.assertRaises(WorkerError):
                execute(job, guard=lambda: None, launch=launch)
        launch.assert_not_called()

    def test_tampered_workspace_path_never_launches(self):
        job = self.job()
        job["argv"] = [x.replace("target=/workspace,readonly", "target=/workspace")
                       for x in job["argv"]]
        launch = mock.Mock()
        with mock.patch("phicortex.worker.platform.system", return_value="Linux"):
            with self.assertRaises(WorkerError):
                execute(job, guard=lambda: None, launch=launch)
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
