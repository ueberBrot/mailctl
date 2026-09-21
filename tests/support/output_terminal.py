"""Capture stdout and stderr independently with optional terminal descriptors."""
import errno
import json
import os
import pty
import selectors
import subprocess
import sys
import time

request = json.load(sys.stdin)
selector = selectors.DefaultSelector()
readers = []
writers = []
for name in ("stdout", "stderr"):
    if request[name]:
        reader, writer = pty.openpty()
    else:
        reader, writer = os.pipe()
    readers.append(reader)
    writers.append(writer)
    selector.register(reader, selectors.EVENT_READ, name)
process = subprocess.Popen(request["command"], stdin=subprocess.DEVNULL,
                           stdout=writers[0], stderr=writers[1])
for writer in writers:
    os.close(writer)
output = {"stdout": bytearray(), "stderr": bytearray()}
deadline = time.monotonic() + 10
try:
    while selector.get_map():
        if time.monotonic() >= deadline:
            raise RuntimeError("output fixture deadline")
        for key, _ in selector.select(0.05):
            try:
                chunk = os.read(key.fd, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            if chunk:
                output[key.data].extend(chunk)
                if len(output[key.data]) > 65536:
                    raise RuntimeError("output fixture limit")
            else:
                selector.unregister(key.fd)
    process.wait(timeout=max(0.01, deadline - time.monotonic()))
finally:
    if process.poll() is None:
        process.kill()
        process.wait()
    for reader in readers:
        os.close(reader)
    selector.close()
json.dump({"exit": process.returncode,
           **{key: value.decode("utf-8") for key, value in output.items()}}, sys.stdout)
