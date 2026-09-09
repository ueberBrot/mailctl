"""Drive a production no-echo prompt with fixture input sent through stdin."""

import errno
import json
import os
import pty
import select
import signal
import sys
import termios
import time

request = json.load(sys.stdin)
pid, terminal = pty.fork()
if pid == 0:
    os.execv(request["command"][0], request["command"])

output = bytearray()
prompted = False
deadline = time.monotonic() + 10
status = None
try:
    while time.monotonic() < deadline:
        ready, _, _ = select.select([terminal], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(terminal, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 65536:
                raise RuntimeError("terminal output exceeded fixture limit")
            if not prompted and any(prompt in bytes(output).lower() for prompt in (b"password:", b"credential:")):
                prompted = True
                if "signal" in request:
                    os.killpg(pid, getattr(signal, request["signal"]))
                elif not request.get("wait"):
                    os.write(terminal, request["secret"].encode() + b"\n")
        if status is None:
            done, child_status = os.waitpid(pid, os.WNOHANG)
            if done:
                status = child_status
    else:
        raise RuntimeError("terminal command exceeded fixture deadline")
finally:
    if status is None:
        done, child_status = os.waitpid(pid, os.WNOHANG)
        if not done:
            os.killpg(pid, signal.SIGKILL)
            _, child_status = os.waitpid(pid, 0)
        status = child_status
    try:
        echo_enabled = bool(termios.tcgetattr(terminal)[3] & termios.ECHO)
    except termios.error:
        echo_enabled = None
    os.close(terminal)

text = output.decode("utf-8", "replace")
json.dump({"exit": os.waitstatus_to_exitcode(status), "prompted": prompted,
           "echo_enabled": echo_enabled,
           "secret_disclosed": bool(request.get("secret")) and request["secret"] in text,
           "output": text}, sys.stdout)
