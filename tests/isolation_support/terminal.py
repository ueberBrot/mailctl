"""Drive a no-echo service-identity credential prompt from an ignored test."""

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
echo_enabled = None
status = None
deadline = time.monotonic() + 10
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
            if not prompted and any(
                prompt in bytes(output).lower() for prompt in (b"password:", b"credential:")
            ):
                prompted = True
                echo_enabled = bool(termios.tcgetattr(terminal)[3] & termios.ECHO)
                os.write(terminal, request["secret"].encode() + b"\n")
        done, child_status = os.waitpid(pid, os.WNOHANG)
        if done:
            status = child_status
            break
    else:
        raise RuntimeError("terminal command exceeded fixture deadline")
finally:
    if status is None:
        done, child_status = os.waitpid(pid, os.WNOHANG)
        if not done:
            os.killpg(pid, signal.SIGKILL)
            _, child_status = os.waitpid(pid, 0)
        status = child_status
    if echo_enabled is None:
        echo_enabled = bool(termios.tcgetattr(terminal)[3] & termios.ECHO)
    os.close(terminal)

text = output.decode("utf-8", "replace")
json.dump(
    {
        "exit": os.waitstatus_to_exitcode(status),
        "prompted": prompted,
        "echo_enabled": echo_enabled,
        "secret_disclosed": request["secret"] in text,
    },
    sys.stdout,
)
