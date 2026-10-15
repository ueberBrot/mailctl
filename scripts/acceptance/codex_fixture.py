"""Disposable TLS IMAP source for the opt-in actual-Codex acceptance runner.

Only the production executable's setup command writes installation state. The
provider serves fixed synthetic data, rejects mutation, and retains no commands,
credentials, message payloads, or other raw protocol transcripts in its summary.
"""

import base64
import collections
import hmac
import imaplib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time


BODY = "Synthetic acceptance: café and 🦀 stay readable. Follow every page to reach the final sentence."
ATTACHMENT = b"abcdef"
FLAGS = ("\\Seen",)
SUBJECT = "Synthetic acceptance digest"
_PASSWORD = "disposable-synthetic-password"
_USERS = {f"synthetic-{color}@example.test" for color in ("blue", "amber")}
_MAX_LINE = 16 * 1024
_HEADERS = b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=synthetic\r\n\r\n"


def _write_private(path, data):
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        output.write(data)


class Fixture:
    """One private installation shared by independently started MCP processes."""

    body = BODY
    flags = FLAGS
    subject = SUBJECT

    def __init__(self, directory, executable, envelope_bytes=None):
        parent = Path(directory).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix="synthetic-imap-", dir=parent))
        self.config = self.directory / "config.toml"
        self.certificate = self.directory / "fixture-ca.pem"
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._sockets = set()
        self._workers = []
        self._counts = collections.Counter()
        self._errors = collections.Counter()
        self._commands = collections.Counter()
        self._listener = None
        self._thread = None
        self._wrong_password_rejected = False
        self._body_bytes = self.body.encode("utf-8")
        self._attachment_bytes = base64.b64encode(ATTACHMENT)
        try:
            self._prepare_certificate()
            self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self._tls.load_cert_chain(self.certificate, self.directory / "fixture-key.pem")
            self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listener.bind(("127.0.0.1", 0))
            self._listener.listen(32)
            self._listener.settimeout(0.2)
            self.port = self._listener.getsockname()[1]
            self._thread = threading.Thread(target=self._accept, daemon=True)
            self._thread.start()
            self._configure(envelope_bytes)
            result = subprocess.run(
                [str(Path(executable).resolve()), "--config", str(self.config), "--json", "setup"],
                env=self.command_env(), cwd=self.directory,
                capture_output=True, timeout=25, check=False,
            )
            try:
                setup_ok = json.loads(result.stdout).get("ok") is True
            except (ValueError, AttributeError):
                setup_ok = False
            if result.returncode != 0 or not setup_ok:
                raise RuntimeError("production fixture setup failed")
            self._probe_wrong_password()
        except BaseException:
            self.close()
            raise

    def _prepare_certificate(self):
        preferred = Path("/opt/homebrew/bin/openssl")
        openssl = str(preferred) if preferred.is_file() else shutil.which("openssl")
        if not openssl:
            raise RuntimeError("OpenSSL is required for the disposable TLS fixture")
        result = subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
             "-addext", "basicConstraints=critical,CA:FALSE",
             "-addext", "extendedKeyUsage=serverAuth",
             "-keyout", str(self.directory / "fixture-key.pem"),
             "-out", str(self.certificate)],
            env={"PATH": "/usr/bin:/bin"}, cwd=self.directory,
            capture_output=True, timeout=20, check=False,
        )
        if result.returncode:
            raise RuntimeError("disposable TLS certificate generation failed")
        os.chmod(self.directory / "fixture-key.pem", 0o600)
        os.chmod(self.certificate, 0o600)

    def _configure(self, envelope_bytes):
        secret = self.directory / "synthetic-credential"
        _write_private(secret, _PASSWORD)
        self._empty_path = self.directory / "empty-path"
        self._empty_path.mkdir(mode=0o700)
        lines = [f"state_dir = {json.dumps(str(self.directory / 'state'))}", "", "[limits]",
                 "wire_fetch_bytes = 2097152", "text_page_bytes = 1024",
                 "attachment_chunk_bytes = 3", "operation_seconds = 15",
                 "account_connections = 2", "account_pending_requests = 2"]
        if envelope_bytes is not None:
            if isinstance(envelope_bytes, bool) or not isinstance(envelope_bytes, int):
                raise ValueError("envelope_bytes must be an integer")
            lines += [f"envelope_bytes = {envelope_bytes}", "active_requests = 4", "queued_requests = 4"]
        for color in ("blue", "amber"):
            alias = f"synthetic-{color}"
            lines += ["", "[[accounts]]", f"key = {json.dumps(alias)}",
                      f"alias = {json.dumps(alias)}", 'server = "127.0.0.1"',
                      f"port = {self.port}", f"username = {json.dumps(alias + '@example.test')}",
                      'mailboxes = ["INBOX"]',
                      f"from_identities = [{json.dumps(alias + '@example.test')}]",
                      "[accounts.credential]", 'source = "command"',
                      f"executable = {json.dumps(str(Path('/bin/cat').resolve()))}",
                      f"args = [{json.dumps(str(secret))}]",
                      f"working_dir = {json.dumps(str(self.directory))}",
                      f"protected_paths = [{json.dumps(str(secret))}]"]
        lines += ["", "[[grants]]", 'name = "default"', 'profile = "read_only"',
                  'accounts = ["synthetic-blue", "synthetic-amber"]', 'mailboxes = ["INBOX"]', ""]
        _write_private(self.config, "\n".join(lines))

    def command_env(self):
        """Minimal environment for production mailctl children, without test hooks."""
        return {"PATH": str(self._empty_path), "SSL_CERT_FILE": str(self.certificate)}

    def _probe_wrong_password(self):
        context = ssl.create_default_context(cafile=str(self.certificate))
        connection = imaplib.IMAP4_SSL("127.0.0.1", self.port, ssl_context=context, timeout=5)
        try:
            try:
                connection.login("synthetic-blue@example.test", "incorrect-synthetic-password")
            except imaplib.IMAP4.error:
                with self._lock:
                    self._wrong_password_rejected = self._counts["rejected_logins"] == 1
            if not self._wrong_password_rejected:
                raise RuntimeError("synthetic provider did not reject the wrong-password probe")
        finally:
            connection.logout()

    def _accept(self):
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            connection.settimeout(5)
            with self._lock:
                self._counts["connections"] += 1
                self._sockets.add(connection)
                worker = threading.Thread(target=self._serve, args=(connection,), daemon=True)
                self._workers.append(worker)
            worker.start()

    def _error(self, reason):
        with self._lock:
            self._errors[reason] += 1

    def _serve(self, connection):
        wire = None
        reader = None
        try:
            wire = self._tls.wrap_socket(connection, server_side=True)
            with self._lock:
                self._sockets.discard(connection)
                self._sockets.add(wire)
                self._counts["active_connections"] += 1
                self._counts["peak_connections"] = max(
                    self._counts["peak_connections"], self._counts["active_connections"])
            reader = wire.makefile("rb")
            wire.sendall(b"* OK synthetic server ready\r\n")
            authenticated = False
            selected = False
            while not self._stop.is_set():
                line = reader.readline(_MAX_LINE + 1)
                if not line:
                    break
                if len(line) > _MAX_LINE or not line.endswith(b"\r\n"):
                    self._error("invalid_line_bound")
                    break
                match = re.fullmatch(rb"([A-Za-z0-9._-]{1,64}) ([\x20-\x7e]+)\r\n", line)
                if not match:
                    self._error("invalid_line")
                    break
                tag, command = (part.decode("ascii") for part in match.groups())
                verb = command.partition(" ")[0].upper()
                safe_verb = verb if verb in {"CAPABILITY", "LOGIN", "LOGOUT", "LIST", "EXAMINE", "UID"} else "REJECTED"
                with self._lock:
                    self._commands[safe_verb] += 1
                if command == "CAPABILITY":
                    wire.sendall(f"* CAPABILITY IMAP4rev1\r\n{tag} OK capability\r\n".encode())
                elif command == "LOGOUT":
                    wire.sendall(f"* BYE synthetic logout\r\n{tag} OK logout\r\n".encode())
                    break
                elif verb == "LOGIN" and not authenticated:
                    try:
                        parts = shlex.split(command)
                    except ValueError:
                        parts = []
                    authenticated = (len(parts) == 3 and parts[1] in _USERS
                                     and hmac.compare_digest(parts[2], _PASSWORD))
                    with self._lock:
                        self._counts["accepted_logins" if authenticated else "rejected_logins"] += 1
                    outcome = "OK authenticated" if authenticated else "NO authentication failed"
                    wire.sendall(f"{tag} {outcome}\r\n".encode())
                elif not authenticated:
                    self._error("unauthenticated_command")
                    wire.sendall(f"{tag} NO authentication required\r\n".encode())
                elif re.fullmatch(r'LIST "" (?:\*|INBOX|"INBOX")', command):
                    if self._stop.wait(0.8):
                        break
                    wire.sendall(f'* LIST () "/" "INBOX"\r\n{tag} OK listed\r\n'.encode())
                elif command in {"EXAMINE INBOX", 'EXAMINE "INBOX"'}:
                    selected = True
                    wire.sendall(f"* 1 EXISTS\r\n* OK [UIDVALIDITY 77] stable\r\n{tag} OK [READ-ONLY] selected\r\n".encode())
                elif selected and self._selected(wire, tag, command):
                    pass
                else:
                    mutating = verb in {"APPEND", "STORE", "EXPUNGE", "CLOSE", "SELECT", "CREATE", "DELETE", "RENAME", "COPY", "MOVE"} or bool(re.match(r"UID (?:STORE|COPY|MOVE|EXPUNGE)\b", command))
                    self._error("mutation_rejected" if mutating else "unexpected_command")
                    wire.sendall(f"{tag} BAD unsupported read-only fixture command\r\n".encode())
                    break
        except socket.timeout:
            if not self._stop.is_set():
                self._error("socket_timeout")
        except (OSError, ssl.SSLError):
            if not self._stop.is_set():
                self._error("connection_closed")
        finally:
            if reader is not None:
                reader.close()
            if wire is not None:
                wire.close()
            connection.close()
            with self._lock:
                self._sockets.discard(connection)
                if wire is not None:
                    self._sockets.discard(wire)
                    self._counts["active_connections"] -= 1

    def _selected(self, wire, tag, command):
        search = re.fullmatch(r"UID SEARCH UID (\*|\d+(?::\d+)?)", command)
        if search:
            sequence = search[1]
            values = sequence.split(":")
            includes = sequence == "*" or (int(values[0]) <= 3 <= int(values[-1]))
            wire.sendall(f"* SEARCH{' 3' if includes else ''}\r\n{tag} OK searched\r\n".encode())
            with self._lock:
                self._commands["UID_SEARCH"] += 1
            return True
        if command == "UID FETCH 3 (UID ENVELOPE FLAGS INTERNALDATE RFC822.SIZE)":
            wire.sendall((f'* 1 FETCH (UID 3 ENVELOPE (NIL "{SUBJECT}" NIL NIL NIL NIL NIL NIL NIL "<synthetic-3@example.test>") '
                          f'FLAGS (\\Seen) INTERNALDATE "15-Oct-2026 12:00:00 +0000" RFC822.SIZE 3000300)\r\n{tag} OK fetched\r\n').encode())
            with self._lock:
                self._commands["UID_FETCH_METADATA"] += 1
            return True
        if command == "UID FETCH 3 (UID RFC822.SIZE BODYSTRUCTURE)":
            structure = (f'(("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "8BIT" {len(self._body_bytes)} 1 NIL NIL NIL NIL)'
                         '("APPLICATION" "OCTET-STREAM" NIL NIL NIL "BASE64" 8 NIL ("ATTACHMENT" ("FILENAME" "synthetic.bin")) NIL NIL) "MIXED" NIL NIL NIL NIL)')
            wire.sendall(f"* 1 FETCH (UID 3 RFC822.SIZE 3000300 BODYSTRUCTURE {structure})\r\n{tag} OK fetched\r\n".encode())
            with self._lock:
                self._commands["UID_FETCH_STRUCTURE"] += 1
            return True
        fetch = re.fullmatch(r"UID FETCH 3 \(UID BODY\.PEEK\[(HEADER|1|2)\]<(\d+)\.(\d+)>\)", command)
        if fetch:
            section, offset, count = fetch[1], int(fetch[2]), int(fetch[3])
            source = {"HEADER": _HEADERS, "1": self._body_bytes, "2": self._attachment_bytes}[section]
            if offset > len(source) or not 1 <= count <= _MAX_LINE:
                self._error("invalid_fetch_range")
                wire.sendall(f"{tag} BAD invalid synthetic range\r\n".encode())
                return True
            payload = source[offset:offset + count]
            wire.sendall(f"* 1 FETCH (UID 3 BODY[{section}]<{offset}> {{{len(payload)}}}\r\n".encode()
                         + payload + f")\r\n{tag} OK fetched\r\n".encode())
            with self._lock:
                self._commands[f"UID_FETCH_{section}"] += 1
            return True
        return False

    def summary(self):
        """Only safe counters and fixed protocol-error codes; never raw payloads."""
        with self._lock:
            return {"counts": dict(self._counts), "commands": dict(self._commands),
                    "errors": dict(self._errors),
                    "wrong_password_rejected": self._wrong_password_rejected}

    def close(self):
        """Stop listener and every owned socket, with a bounded total join time."""
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
        with self._lock:
            connections = list(self._sockets)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        deadline = time.monotonic() + 3
        if self._thread is not None:
            self._thread.join(max(0, deadline - time.monotonic()))
        with self._lock:
            workers = list(self._workers)
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))
