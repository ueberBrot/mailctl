"""Offline checks for bounded cleanup, fixture deadlines and acceptance evidence."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_fixture
import codex_mcp


class TraceTests(unittest.TestCase):
    def test_inherited_pipes_do_not_keep_runner_alive(self):
        with tempfile.TemporaryDirectory(prefix="mailctl-inherited-pipe-") as temporary:
            directory = Path(temporary)
            holder_pid = directory / "holder.pid"
            # Escape the client's group while keeping both output pipes open.
            client = (
                "import pathlib, subprocess, sys\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import os, time; os.write(1, b\"{\"); os.write(2, b\"partial\"); time.sleep(60)'], "
                "start_new_session=True)\n"
                f"pathlib.Path({str(holder_pid)!r}).write_text(str(child.pid))\n"
            )
            runner = textwrap.dedent(f"""
                import json, pathlib, sys, threading
                sys.path.insert(0, {str(Path(codex_mcp.__file__).parent)!r})
                import codex_mcp
                status, _, _ = codex_mcp.run_agent(
                    [sys.executable, '-c', {client!r}], 'synthetic prompt' * 100000,
                    2, pathlib.Path({temporary!r}))
                print(json.dumps({{'status': status, 'threads': len(threading.enumerate())}}), flush=True)
            """)
            process = subprocess.Popen([sys.executable, "-c", runner], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=7)
                self.assertEqual(process.returncode, 0, stderr.decode())
                result = json.loads(stdout)
                self.assertEqual(result["threads"], 1)
                self.assertFalse(result["status"]["cleanup_confirmed"])
                self.assertFalse(result["status"]["timed_out"])
            finally:
                # Also run on regression failure: neither disposable group may survive.
                if holder_pid.exists():
                    try:
                        os.killpg(int(holder_pid.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=3)

    def test_deadline_also_bounds_a_child_that_does_not_read_prompt(self):
        with tempfile.TemporaryDirectory(prefix="mailctl-client-timeout-") as temporary:
            started = time.monotonic()
            status, calls, answers = codex_mcp.run_agent(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                "synthetic prompt" * 100000, 0.2, Path(temporary),
            )
            self.assertTrue(status["timed_out"])
            self.assertLess(time.monotonic() - started, 6)
            self.assertEqual((calls, answers), ([], []))

    def test_proxy_preserves_bytes_and_excludes_payloads(self):
        with tempfile.TemporaryDirectory(prefix="mailctl-proxy-test-") as temporary:
            directory = Path(temporary)
            executable = directory / "echo-server"
            executable.write_text(
                "#!" + sys.executable + "\n"
                "import sys\n"
                "for line in sys.stdin.buffer:\n"
                "    sys.stdout.buffer.write(line)\n"
                "    sys.stdout.buffer.flush()\n"
            )
            executable.chmod(0o700)
            trace = directory / "trace.jsonl"
            payload = (
                b'{ "jsonrpc":"2.0", "id":1, "method":"initialize", '
                b'"params":{"synthetic_secret":"NEVER_TRACE_PAYLOAD"}}\n'
                b'{"jsonrpc":"2.0","id":2,"method":"tools/call",'
                b'"params":{"text":"caf\\u00e9"}}\n'
            )
            result = subprocess.run(
                [sys.executable, str(Path(codex_mcp.__file__).resolve()), "--proxy",
                 str(executable), str(directory / "config.toml"), "unused-cert",
                 str(trace), "test"], input=payload, capture_output=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, payload)
            self.assertNotIn("NEVER_TRACE_PAYLOAD", trace.read_text())
            for line in trace.read_text().splitlines():
                self.assertEqual(set(json.loads(line)), {"time_ns", "pid", "method", "id", "code"})

    def test_request_overlap_is_measured_before_response(self):
        with tempfile.TemporaryDirectory(prefix="mailctl-overlap-test-") as temporary:
            trace = Path(temporary) / "trace.jsonl"
            frames = [("process_start", None, None), ("tools/call", 1, "request"),
                      ("tools/call", 2, "request"), ("tools/call", 2, -32000),
                      ("tools/call", 1, "ok"), ("process_exit", None, 0)]
            trace.write_text("".join(json.dumps({"time_ns": index * 1000000, "pid": 10,
                                                "method": method, "id": request_id, "code": code}) + "\n"
                                     for index, (method, request_id, code) in enumerate(frames)))
            result = codex_mcp.transport_summary(trace)
            self.assertEqual(result["max_outstanding_tool_requests"], 2)
            self.assertEqual(result["unanswered_requests"], 0)
            self.assertEqual(result["responses"][0]["code"], -32000)
            self.assertEqual(result["responses"][1]["duration_ms"], 3)


class DeadlineTests(unittest.TestCase):
    def test_preparation_subprocesses_share_the_remaining_budget(self):
        with tempfile.TemporaryDirectory(prefix="mailctl-fixture-deadline-") as temporary:
            fixture = codex_fixture.Fixture.__new__(codex_fixture.Fixture)
            fixture.directory = Path(temporary)
            fixture.certificate = fixture.directory / "certificate.pem"
            fixture._deadline = time.monotonic() + 0.1
            with patch.object(codex_fixture.subprocess, "run", side_effect=subprocess.TimeoutExpired("openssl", 0.1)) as run:
                with self.assertRaises(subprocess.TimeoutExpired):
                    fixture._prepare_certificate()
            self.assertLessEqual(run.call_args.kwargs["timeout"], 0.1)

    def test_expired_second_profile_does_not_start_preparation(self):
        with tempfile.TemporaryDirectory(prefix="mailctl-fixture-expired-") as temporary:
            with patch.object(codex_fixture.subprocess, "run") as run:
                with self.assertRaises(TimeoutError):
                    codex_fixture.Fixture(Path(temporary), Path("unused"),
                                          deadline=time.monotonic() - 1)
            run.assert_not_called()

    def test_setup_timeout_closes_the_partly_prepared_fixture(self):
        with tempfile.TemporaryDirectory(prefix="mailctl-setup-deadline-") as temporary:
            executable = Path(temporary) / "slow-setup"
            executable.write_text("#!" + sys.executable + "\nimport time; time.sleep(30)\n")
            executable.chmod(0o700)
            started = time.monotonic()
            with patch.object(codex_fixture.Fixture, "_prepare_certificate"), \
                    patch.object(codex_fixture.ssl, "SSLContext"), \
                    patch.object(codex_fixture.Fixture, "close", autospec=True,
                                 side_effect=codex_fixture.Fixture.close) as close:
                with self.assertRaises(subprocess.TimeoutExpired):
                    codex_fixture.Fixture(Path(temporary), executable, deadline=started + 0.2)
            self.assertLess(time.monotonic() - started, 2)
            fixture = close.call_args.args[0]
            self.assertEqual(fixture._listener.fileno(), -1)
            self.assertFalse(fixture._thread.is_alive())

    def test_whole_wrong_password_exchange_uses_remaining_budget(self):
        fixture = codex_fixture.Fixture.__new__(codex_fixture.Fixture)
        fixture.certificate = Path("unused-certificate")
        fixture._empty_path = Path("unused-path")
        fixture.port = 12345
        fixture._deadline = time.monotonic() + 0.1
        with patch.object(codex_fixture.subprocess, "run", side_effect=subprocess.TimeoutExpired("probe", 0.1)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                fixture._probe_wrong_password()
        self.assertLessEqual(run.call_args.kwargs["timeout"], 0.1)


class EvaluationTests(unittest.TestCase):
    def discovery(self):
        return {"server": "mail_a", "tool": "email_list_mailboxes",
                "arguments": {"account": "synthetic-amber"},
                "result": {"structuredContent": {"ok": True, "result": {
                    "mailboxes": [{"reference": "opaque-amber-inbox",
                                   "metadata": {"name": "INBOX"}}]}}}}

    def denial(self):
        return {"server": "mail_b", "tool": "email_search_messages",
                "arguments": {"mailbox": "opaque-amber-inbox", "criteria": [], "limit": 1},
                "result": {"structuredContent": {"ok": False,
                           "error": {"code": "account_not_allowed"}}}}

    def accepted(self, calls):
        return codex_mcp.evaluate(calls, SimpleNamespace(body=""))["peer_amber_mailbox_search_denied"]

    def test_denial_matches_previously_discovered_amber_mailbox(self):
        self.assertTrue(self.accepted([self.discovery(), self.denial()]))

    def test_unrelated_denials_do_not_satisfy_acceptance(self):
        for field, value in (("server", "mail_a"), ("tool", "email_list_mailboxes"),
                             ("arguments", {"mailbox": "other-reference"}),
                             ("arguments", {"account": "synthetic-amber"})):
            with self.subTest(field=field, value=value):
                denied = self.denial()
                denied[field] = value
                self.assertFalse(self.accepted([self.discovery(), denied]))

    def test_denial_requires_successful_prior_inbox_discovery(self):
        self.assertFalse(self.accepted([self.denial()]))
        self.assertFalse(self.accepted([self.denial(), self.discovery()]))
        for alteration in ("failed", "other_account", "other_mailbox"):
            with self.subTest(alteration=alteration):
                discovery = self.discovery()
                if alteration == "failed":
                    discovery["result"]["structuredContent"] = {
                        "ok": False, "error": {"code": "account_not_allowed"}}
                elif alteration == "other_account":
                    discovery["arguments"]["account"] = "synthetic-blue"
                else:
                    discovery["result"]["structuredContent"]["result"]["mailboxes"][0]["metadata"]["name"] = "Archive"
                self.assertFalse(self.accepted([discovery, self.denial()]))


if __name__ == "__main__":
    unittest.main()
