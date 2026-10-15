#!/usr/bin/env python3
"""Opt-in actual Codex client acceptance; never invoked by ordinary CI."""

import argparse
import base64
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

from codex_fixture import Fixture, remaining


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            hasher.update(block)
    return hasher.hexdigest()


def proxy(arguments):
    """Forward exact JSONL bytes without delaying or manufacturing requests."""
    executable, config, certificate, trace, runtime, *narrow = arguments
    environment = {"PATH": str(Path(config).parent / "empty-path"),
                   "SSL_CERT_FILE": certificate}
    child = subprocess.Popen([executable, "--config", config, *narrow],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env=environment)
    lock = threading.Lock()
    methods = {}
    output = open(trace, "a", buffering=1)

    def stop(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)

    def record(method, request_id=None, code=None):
        # Never persist params, content, credentials, or arbitrary error text.
        value = {"time_ns": time.monotonic_ns(), "pid": child.pid,
                 "method": method, "id": request_id, "code": code}
        with lock:
            output.write(json.dumps(value) + "\n")

    def observe(line, direction):
        try:
            frame = json.loads(line)
            request_id = frame.get("id")
            if not isinstance(request_id, (int, str, type(None))):
                request_id = None
            if isinstance(request_id, str) and not re.fullmatch(r"[\w-]{1,80}", request_id):
                request_id = "redacted"
            if direction == "request":
                method = frame.get("method", "unknown")
                if not re.fullmatch(r"[A-Za-z_/]{1,80}", method):
                    method = "unknown"
                methods[request_id] = method
                record(method, request_id, "request")
            else:
                code = "ok"
                if "error" in frame:
                    code = frame["error"].get("code", "rpc_error")
                else:
                    result = frame.get("result", {})
                    structured = result.get("structuredContent", {})
                    if structured.get("ok") is False:
                        code = structured.get("error", {}).get("code", "application_error")
                if not isinstance(code, int) and not re.fullmatch(r"[a-z_]{1,80}", str(code)):
                    code = "redacted"
                record(methods.get(request_id, "notification"), request_id, code)
        except (ValueError, AttributeError, TypeError):
            record("invalid_frame", code="parse_error")

    def ingress():
        try:
            for line in sys.stdin.buffer:
                observe(line, "request")
                child.stdin.write(line)
                child.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            child.stdin.close()

    record("process_start")
    threading.Thread(target=ingress, daemon=True).start()
    try:
        for line in child.stdout:
            observe(line, "response")
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)
        record("process_exit", code=child.returncode)
        output.close()


def transport_summary(path):
    events = [json.loads(line) for line in path.read_text().splitlines()]
    pending = {}
    maximum = 0
    tool_pending = set()
    maximum_tools = 0
    intervals = []
    for event in events:
        key = event["id"]
        if event["code"] == "request" and key is not None:
            pending[key] = event
            if event["method"] == "tools/call":
                tool_pending.add(key)
            maximum = max(maximum, len(pending))
            maximum_tools = max(maximum_tools, len(tool_pending))
        elif key in pending:
            first = pending.pop(key)
            tool_pending.discard(key)
            intervals.append({"method": event["method"], "id": key,
                              "request_ns": first["time_ns"], "response_ns": event["time_ns"],
                              "duration_ms": round((event["time_ns"] - first["time_ns"]) / 1e6, 3),
                              "code": event["code"]})
    starts = [e["time_ns"] for e in events if e["method"] == "process_start"]
    ends = [e["time_ns"] for e in events if e["method"] == "process_exit"]
    initialized = [e["time_ns"] for e in events if e["method"] == "initialize" and e["code"] == "ok"]
    discovered = [e["time_ns"] for e in events if e["method"] == "tools/list" and e["code"] == "ok"]
    initializing = [e["time_ns"] for e in events if e["method"] == "initialize" and e["code"] == "request"]
    discovering = [e["time_ns"] for e in events if e["method"] == "tools/list" and e["code"] == "request"]
    return {"pid": events[0]["pid"], "start_ns": min(starts),
            "exit_ns": max(ends) if ends else None,
            "initialized_ns": min(initialized) if initialized else None,
            "discovered_ns": min(discovered) if discovered else None,
            "initialize_request_ns": min(initializing) if initializing else None,
            "discovery_request_ns": min(discovering) if discovering else None,
            "max_outstanding_requests": maximum,
            "max_outstanding_tool_requests": maximum_tools,
            "unanswered_requests": len(pending), "responses": intervals}


WORKFLOW = """You are a fresh consuming application evaluating public mailctl documentation.
Only use the connected mail_a and mail_b tools/resources and the public material below.
All connected accounts/data are synthetic, locally provisioned by the operator. Do not
use shell, other servers, web, configuration, credentials, or implementation files.
Do not create or send any email. Do not invoke setup or credential commands.

Inspect both runtimes' capabilities, available accounts, public guides and input/output
schemas. Discover the accounts rather than inventing aliases or reference values.
First perform a capacity probe: submit six independent mailbox-list calls to mail_a
for the discovered synthetic-blue account concurrently in one parallel tool batch,
using distinct limit values 1, 2, 3, 4, 5, 6 for the six calls.
Repeat this probe on mail_b. Do not intentionally serialize or stagger a probe.
Report all outcomes, then continue the workflow even if some probes were refused.

Find the INBOX synthetic message in synthetic-blue. Read its entire selected text
through mail_a using a 32-byte page budget. Record its exact assembled text and the
representation metadata you would retain to compare a future rendering. Use mail_b
to read that same message reference. Also discover the INBOX reference for
synthetic-amber in mail_a and try searching that reference through mail_b once.
Explain the results.

List the blue message's attachments and begin a transfer through mail_a. A teammate
hands mail_b that attachment reference, the unfinished transfer token, and the partial
assembly. Demonstrate what happens if mail_b uses the token, then finish retrieval
correctly through mail_b. Report how a consuming application checks its assembly;
do not treat base64 as message prose.

A separate hypothetical draft task has a caller-owned persisted record containing
the original account UUID/generation, operation UUID, Drafts mailbox and exact
composition. Its last save returned outcome_unknown after the connection broke.
Describe the exact next status/recovery inputs, what to keep across process restart
or alias changes, and which observations establish completion. Do not execute this
draft task. Include what you would do if verification remains inconclusive.

Return a JSON object containing: accounts_and_permissions, capacity_observations,
assembled_text, representation_metadata, handoff_observations, attachment_validation,
draft_recovery, unresolved. Separate actual observations from proposed actions.
"""


def public_material(binary, readme):
    # The consuming model receives public docs, never repository/private task context.
    pieces = [("README", readme.read_text())]
    for args in (["--help"], ["schema", "save_draft"], ["schema", "draft_status"]):
        result = subprocess.run([str(binary), *args], capture_output=True, text=True,
                                timeout=15, check=True)
        pieces.append(("mailctl-mcp " + " ".join(args), result.stdout))
    return "\n\n".join(title + "\n" + body for title, body in pieces)


def command(codex, model, workspace, binary, fixture, output):
    servers = {}
    for name, narrowing in (("mail_a", []), ("mail_b", ["--account", "synthetic-blue"])):
        servers[name] = {"command": sys.executable,
                         "args": [str(Path(__file__).resolve()), "--proxy", str(binary),
                                  str(fixture.config), str(fixture.certificate),
                                  str(output / (name + ".jsonl")), name, *narrowing],
                         "startup_timeout_sec": 30, "tool_timeout_sec": 30}
    # JSON quoting strings is valid TOML basic-string syntax for these paths.
    def toml(value):
        if isinstance(value, dict):
            return "{" + ",".join(json.dumps(k) + "=" + toml(v) for k, v in value.items()) + "}"
        if isinstance(value, list):
            return "[" + ",".join(toml(v) for v in value) + "]"
        return json.dumps(value)
    result = [str(codex), "exec", "--strict-config", "--ignore-user-config", "--ignore-rules", "--ephemeral",
              "--json", "--sandbox", "read-only", "--skip-git-repo-check", "-C", str(workspace),
              "-c", "project_doc_max_bytes=0", "-c", 'web_search="disabled"',
              "-c", "features.shell_tool=false", "-c", "features.apps=false",
              "-c", "features.plugins=false", "-c", "features.multi_agent=false",
              "-c", "features.skill_search=false", "-c", "features.skip_host_skill_discovery=true",
              "-c", "mcp_servers=" + toml(servers), "-"]
    if model:
        result[2:2] = ["--model", model]
    return result


def run_agent(arguments, prompt, timeout, output):
    environment = {k: v for k, v in os.environ.items()
                   if k in {"HOME", "CODEX_HOME", "PATH", "TMPDIR", "LANG", "LC_ALL"}}
    child = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=environment, start_new_session=True)
    events, errors = [], []
    stopping = threading.Event()

    def read_lines(stream, receive):
        pending = b""
        while not stopping.is_set():
            if not select.select([stream], [], [], 0.05)[0]:
                continue
            block = os.read(stream.fileno(), 65536)
            if not block:
                if pending:
                    receive(pending)
                return
            lines = (pending + block).split(b"\n")
            pending = lines.pop()
            for line in lines:
                receive(line)
        errors.append("cleanup_reader_incomplete")

    def consume(line):
        try:
            event = json.loads(line)
        except ValueError:
            errors.append("invalid_json_event")
            return
        event["_received_ns"] = time.monotonic_ns()
        events.append(event)

    # Drain diagnostics without retaining potentially sensitive arbitrary messages.
    def diagnostics(_line):
        errors.append("stderr_line")

    readers = [threading.Thread(target=read_lines, args=(stream, receive), daemon=True)
               for stream, receive in ((child.stdout, consume), (child.stderr, diagnostics))]
    for reader in readers:
        reader.start()
    expired = False

    def deliver():
        try:
            os.set_blocking(child.stdin.fileno(), False)
            pending = memoryview(prompt.encode())
            while pending and not stopping.is_set():
                if select.select([], [child.stdin], [], 0.05)[1]:
                    try:
                        pending = pending[os.write(child.stdin.fileno(), pending[:65536]):]
                    except BlockingIOError:
                        pass
            if pending:
                errors.append("cleanup_writer_incomplete")
        except (BrokenPipeError, OSError):
            errors.append("prompt_delivery_failed")
        finally:
            try:
                child.stdin.close()
            except (BrokenPipeError, OSError):
                pass

    writer = threading.Thread(target=deliver, daemon=True)
    writer.start()
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        expired = True
    finally:
        # MCP children share the owned process group. Close every owned descendant.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            errors.append("cleanup_permission_denied")
        cleanup_deadline = time.monotonic() + 3
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        # The leader may already have exited while proxies are still recording
        # their exit. Give the entire owned group a bounded grace without using
        # signal 0, which some managed sandboxes prohibit.
        time.sleep(max(0, cleanup_deadline - time.monotonic()))
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            errors.append("cleanup_permission_denied")
            if child.poll() is None:
                child.kill()
        child.wait(timeout=3)
        # A descendant can leave the group while retaining a pipe. Readers must
        # stop even when neither EOF nor another complete line arrives.
        drain_deadline = time.monotonic() + 0.2
        for worker in [*readers, writer]:
            worker.join(max(0, drain_deadline - time.monotonic()))
        stopping.set()
        join_deadline = time.monotonic() + 0.2
        for worker in [*readers, writer]:
            worker.join(max(0, join_deadline - time.monotonic()))
        if any(worker.is_alive() for worker in [*readers, writer]):
            errors.append("cleanup_worker_incomplete")
        child.stdout.close()
        child.stderr.close()
    sanitized = []
    calls = []
    answers = []
    started = {}
    for event in events:
        item = event.get("item", {})
        entry = {"type": event.get("type"), "item_type": item.get("type"),
                 "time_ns": event["_received_ns"]}
        if event.get("type") == "item.started":
            started[item.get("id")] = event["_received_ns"]
        if item.get("type") == "mcp_tool_call":
            entry.update({k: item[k] for k in ("server", "tool", "status") if k in item})
            if event.get("type") == "item.completed":
                item["_started_ns"] = started.get(item.get("id"))
                item["_finished_ns"] = event["_received_ns"]
                calls.append(item)
        if item.get("type") == "agent_message" and event.get("type") == "item.completed":
            answers.append(item.get("text", ""))
        sanitized.append(entry)
    write_json(output / "client-events.json", sanitized)
    # Final answers may quote only the explicitly synthetic fixture/public material.
    (output / "agent-answer.txt").write_text("\n".join(answers) + "\n")
    return {"exit_code": child.returncode, "timed_out": expired,
            "cleanup_confirmed": not any(code.startswith("cleanup_") for code in errors),
            "diagnostic_lines": len(errors), "event_count": len(events)}, calls, answers


def envelope(item):
    result = item.get("result") or {}
    structured = result.get("structuredContent") or result.get("structured_content")
    if structured:
        return structured
    for block in result.get("content", []):
        if block.get("type") == "text":
            try:
                value = json.loads(block["text"])
                if isinstance(value, dict) and "ok" in value:
                    return value
            except ValueError:
                pass
    return {}


def evaluate(calls, fixture):
    observed = collections.Counter()
    pages = []
    codes = collections.Counter()
    versions = set()
    capacity = {}
    successful_discovery = set()
    guides = {server: set() for server in ("mail_a", "mail_b")}
    probes = {server: {} for server in ("mail_a", "mail_b")}
    peer_reads = []
    attachments = {server: [] for server in ("mail_a", "mail_b")}
    amber_inboxes = set()
    peer_amber_denied = False
    for item in calls:
        observed[(item.get("server"), item.get("tool"))] += 1
        result = envelope(item)
        args = item.get("arguments", {})
        server = item.get("server")
        tool = item.get("tool")
        if server == "mail_a" and tool == "email_list_mailboxes" and args.get("account") == "synthetic-amber" and result.get("ok"):
            amber_inboxes.update(mailbox["reference"] for mailbox in result["result"].get("mailboxes", [])
                                 if mailbox.get("metadata", {}).get("name") == "INBOX" and mailbox.get("reference"))
        if (server == "mail_b" and tool == "email_search_messages" and
                args.get("mailbox") in amber_inboxes and result.get("ok") is False and
                result.get("error", {}).get("code") == "account_not_allowed"):
            peer_amber_denied = True
        if result.get("ok") and tool in ("email_capabilities", "email_list_accounts"):
            successful_discovery.add((server, tool))
        if server in guides and tool == "read_mcp_resource" and item.get("result") and not item.get("error"):
            uri = args.get("uri")
            if uri in {"mailctl://guide/" + topic for topic in ("overview", "reading", "attachments", "drafts", "errors")}:
                guides[server].add(uri)
        if server in probes and tool == "email_list_mailboxes" and args.get("account") == "synthetic-blue" and args.get("limit") in range(1, 7):
            probes[server].setdefault(args["limit"], {
                "limit": args["limit"], "ok": result.get("ok"),
                "code": result.get("error", {}).get("code", "ok" if result.get("ok") else "rpc_error"),
                "started_ns": item.get("_started_ns"), "finished_ns": item.get("_finished_ns")})
        if server == "mail_b" and tool == "email_get_message" and result.get("ok"):
            peer_reads.append((args, result["result"]["body"]))
        if server in attachments and tool == "email_get_attachment":
            attachments[server].append((args, result))
        if item.get("tool") == "email_capabilities" and result.get("ok"):
            capacity[item.get("server")] = {
                "capacity": result["result"].get("capacity"),
                "limits": result["result"].get("limits")}
        if result.get("ok") is False:
            codes[result["error"]["code"]] += 1
        if item.get("server") == "mail_a" and item.get("tool") == "email_get_message" and result.get("ok"):
            body = result["result"]["body"]
            pages.append((args, body))
            if isinstance(body.get("representation_version"), str):
                versions.add(body["representation_version"])
    assembly = "".join(body["text"] for _, body in pages)
    contiguous = bool(pages) and not pages[0][0].get("cursor") and all(
        pages[index][0].get("message") == pages[0][0].get("message") and
        pages[index][0].get("cursor") == pages[index - 1][1].get("next_cursor")
        for index in range(1, len(pages)))
    attachment_bytes = bytearray()
    attachment_valid = False
    attachment_restarted = False
    token_rejected = False
    if attachments["mail_a"]:
        original_args, original = attachments["mail_a"][0]
        original_token = original.get("result", {}).get("progress", {}).get("next_token")
        next_token = None
        for args, result in attachments["mail_b"]:
            if args.get("token") == original_token and result.get("error", {}).get("code") == "transfer_expired":
                token_rejected = True
            if not result.get("ok"):
                continue
            chunk = result["result"]
            if args.get("attachment") == original_args.get("attachment"):
                attachment_bytes = bytearray()
                attachment_restarted = True
            elif not next_token or args.get("token") != next_token:
                break
            if chunk.get("decoded_offset") != len(attachment_bytes):
                break
            try:
                attachment_bytes.extend(base64.b64decode(chunk["bytes_base64"], validate=True))
            except (ValueError, KeyError):
                break
            progress = chunk["progress"]
            next_token = progress.get("next_token")
            if progress.get("status") == "complete":
                attachment_valid = (bytes(attachment_bytes) == b"abcdef" and
                                    progress.get("total_decoded_bytes") == len(attachment_bytes) and
                                    progress.get("sha256") == hashlib.sha256(attachment_bytes).hexdigest())
    for values in probes.values():
        intervals = [(p["started_ns"], p["finished_ns"]) for p in values.values() if p["started_ns"]]
        peak = max((sum(begin <= point < end for begin, end in intervals)
                    for point, _ in intervals), default=0)
        # Safe outcome metadata; no account identities/references/payloads retained.
        for p in values.values():
            p["client_probe_peak"] = peak
    return {"calls": [{"server": server, "tool": tool, "count": count}
                       for (server, tool), count in sorted(observed.items())],
            "application_codes": dict(codes), "body_pages": len(pages),
            "reported_capacity": capacity,
            "mailbox_probes": {server: sorted(values.values(), key=lambda p: p["limit"])
                               for server, values in probes.items()},
            "mailbox_probe_calls": {server: observed[(server, "email_list_mailboxes")]
                                    for server in ("mail_a", "mail_b")},
            "body_assembled_exactly": assembly == fixture.body,
            "body_page_budget_preserved": bool(pages) and all(
                args.get("max_bytes") == 32 and len(body["text"].encode()) <= 32
                for args, body in pages),
            "body_completed": bool(pages) and pages[-1][1].get("continuation_available") is False,
            "body_cursor_chain_preserved": contiguous,
            "body_representation_versions": sorted(versions),
            "all_body_pages_versioned": bool(pages) and all(body.get("representation_version") for _, body in pages),
            "peer_reference_read": bool(pages) and any(
                args.get("message") == pages[0][0].get("message") and not args.get("cursor") and
                bool(body.get("text")) and fixture.body.startswith(body["text"])
                for args, body in peer_reads),
            "peer_amber_mailbox_search_denied": peer_amber_denied,
            "foreign_transfer_token_rejected": token_rejected,
            "attachment_restarted_in_peer": attachment_restarted,
            "attachment_bytes_offsets_size_digest_verified": attachment_valid,
            "successful_guide_reads": {server: sorted(uris) for server, uris in guides.items()},
            "both_discovered": all((server, tool) in successful_discovery for server in ("mail_a", "mail_b")
                                   for tool in ("email_capabilities", "email_list_accounts")),
            "no_draft_tool_calls": all("draft" not in tool for _, tool in observed)}


def main():
    os.umask(0o077)

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="authorize actual authenticated model execution")
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--codex", type=Path, default=Path("/opt/homebrew/bin/codex"))
    parser.add_argument("--model", help="optional exact model; otherwise Codex's clean default")
    parser.add_argument("--provenance", choices=("source-provisional", "packaged"), required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--readme", type=Path, help="README from the selected candidate source")
    parser.add_argument("--profile", choices=("small", "default", "both"), default="both")
    parser.add_argument("--timeout", type=int, default=240,
                        help="combined fixture/client deadline in seconds; bounded cleanup follows")
    parser.add_argument("--output", type=Path, help="new private evidence directory; defaults to temporary")
    args = parser.parse_args()
    if not args.run:
        parser.error("--run is required; this opt-in check uses the current native Codex account")
    if not 30 <= args.timeout <= 600:
        parser.error("--timeout must be between 30 and 600 seconds")
    repository = Path(__file__).resolve().parents[2]
    readme = args.readme or repository / "README.md"
    selected_binary = args.bin_dir.resolve() / "mailctl-mcp"
    args.codex = args.codex.resolve()
    output = args.output or Path(tempfile.mkdtemp(prefix="mailctl-codex-evidence-"))
    if args.output:
        output.mkdir(mode=0o700)
    output = output.resolve()
    os.chmod(output, 0o700)
    # All-target Cargo builds can replace a debug executable while acceptance is
    # running. Both profiles must launch the same verified production bytes.
    binary = output / "mailctl-mcp-snapshot"
    shutil.copyfile(selected_binary, binary)
    binary.chmod(0o700)
    if digest(binary) != digest(selected_binary):
        raise RuntimeError("selected executable changed while taking the acceptance snapshot")
    provenance = {"qualification": args.provenance, "candidate_commit": args.candidate_commit,
                  "mcp_sha256": digest(binary), "codex_sha256": digest(args.codex),
                  "selected_mcp_path": str(selected_binary),
                  "readme_sha256": digest(readme),
                  "codex_version": subprocess.check_output([str(args.codex), "--version"], text=True, timeout=10).strip(),
                  "mcp_version": subprocess.check_output([str(binary), "--version"], text=True, timeout=10).strip(),
                  "harness_sha256": digest(Path(__file__).resolve()),
                  "fixture_sha256": digest(Path(__file__).with_name("codex_fixture.py")),
                  "source_base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True, timeout=10).strip(),
                  "source_delta_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "--", "src"], cwd=repository, timeout=10)).hexdigest(),
                  "platform": {"system": os.uname().sysname, "release": os.uname().release,
                               "machine": os.uname().machine}, "model_requested": args.model,
                  "credential_source": "disposable protected command credential",
                  "tls_trust": "disposable SSL_CERT_FILE", "publication": "not-performed"}
    write_json(output / "provenance.json", provenance)
    public = public_material(binary, readme)
    deadline = time.monotonic() + args.timeout
    profiles = ("small", "default") if args.profile == "both" else (args.profile,)
    summaries = {}
    for profile in profiles:
        run_output = output / profile
        run_output.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="mailctl-codex-fixture-") as directory:
            remaining(deadline)
            fixture = Fixture(Path(directory), binary, 65536 if profile == "small" else None,
                              deadline=deadline)
            workspace = Path(directory) / "agent-workspace"
            workspace.mkdir()
            prompt = WORKFLOW + "\n\n" + public
            (run_output / "workflow.txt").write_text(prompt)
            arguments = command(args.codex, args.model, workspace, binary, fixture, run_output)
            write_json(run_output / "invocation.json", arguments)
            try:
                status, calls, _ = run_agent(arguments, prompt, remaining(deadline), run_output)
                summary = {"client": status, "behavior": evaluate(calls, fixture)}
            finally:
                fixture.close()
            summary["provider"] = fixture.summary()
            summary["transport"] = {name: transport_summary(run_output / (name + ".jsonl"))
                                    for name in ("mail_a", "mail_b")
                                    if (run_output / (name + ".jsonl")).exists()}
            transports = list(summary["transport"].values())
            summary["natural_process_overlap"] = len(transports) == 2 and all(
                t["exit_ns"] is not None for t in transports) and max(t["start_ns"] for t in transports) < min(
                    t["exit_ns"] for t in transports)
            for stage in ("initialized", "discovered"):
                begin = "initialize_request_ns" if stage == "initialized" else "discovery_request_ns"
                summary["natural_" + stage + "_overlap"] = len(transports) == 2 and all(
                    t[stage + "_ns"] is not None and t[begin] is not None for t in transports) and max(
                        t[begin] for t in transports) < min(t[stage + "_ns"] for t in transports)
            summary["process_start_delta_ms"] = (round(abs(transports[0]["start_ns"] - transports[1]["start_ns"]) / 1e6, 3)
                                                 if len(transports) == 2 else None)
            summary["parallel_client_tool_requests"] = len(transports) == 2 and all(
                t["max_outstanding_tool_requests"] >= 2 for t in transports)
            # Semantic draft/permission/transfer explanations require human review of
            # agent-answer.txt. Mechanical success alone does not close issue #18.
            summary["mechanical_pass"] = all((
                status["exit_code"] == 0, not status["timed_out"],
                status["cleanup_confirmed"],
                summary["natural_process_overlap"], summary["parallel_client_tool_requests"],
                summary["natural_initialized_overlap"],
                summary["behavior"]["both_discovered"], summary["behavior"]["body_assembled_exactly"],
                summary["behavior"]["body_page_budget_preserved"], summary["behavior"]["body_completed"],
                summary["behavior"]["body_cursor_chain_preserved"],
                len(summary["behavior"]["body_representation_versions"]) == 1,
                summary["behavior"]["all_body_pages_versioned"],
                summary["behavior"]["peer_reference_read"],
                summary["behavior"]["foreign_transfer_token_rejected"],
                summary["behavior"]["attachment_restarted_in_peer"],
                summary["behavior"]["attachment_bytes_offsets_size_digest_verified"],
                summary["behavior"]["peer_amber_mailbox_search_denied"],
                summary["behavior"]["no_draft_tool_calls"],
                all(len(probes) == 6 and all(p["client_probe_peak"] >= 2 for p in probes)
                    for probes in summary["behavior"]["mailbox_probes"].values()),
                all(len(uris) == 5 for uris in summary["behavior"]["successful_guide_reads"].values()),
                not summary["provider"]["errors"], summary["provider"]["wrong_password_rejected"]))
            summaries[profile] = summary
            write_json(run_output / "summary.json", summary)
            print(profile + ": " + ("mechanical pass" if summary["mechanical_pass"] else "incomplete"), flush=True)
    write_json(output / "summary.json", summaries)
    print("Evidence: " + str(output))
    return 0 if all(s["mechanical_pass"] for s in summaries.values()) else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--proxy":
        proxy(sys.argv[2:])
    else:
        sys.exit(main())
