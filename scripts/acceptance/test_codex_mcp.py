"""Offline regression checks for payload-free, byte-preserving acceptance tracing."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

import codex_mcp


class TraceTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
