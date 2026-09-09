"""Small adversarial Unix-socket probes for the native qualification."""

import os
import json
import socket
import struct
import sys
import time

mode, path = sys.argv[1:]

def read_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected gateway EOF")
        data.extend(chunk)
    return bytes(data)

if mode in ("hold", "initialization-timeout", "null-hello", "account-hello", "unauthorized-hello"):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(3)
    connection.connect(path)
if mode in ("hold", "null-hello", "account-hello", "unauthorized-hello"):
    accounts = b'["work"]' if mode == "account-hello" else b"null"
    hello = (b'{"type":"hello","version":1,"narrowing":'
             b'{"read_only":false,"accounts":' + accounts + b"}}")
    try:
        connection.sendall(struct.pack(">I", len(hello)) + hello)
    except (BrokenPipeError, ConnectionResetError):
        if mode != "unauthorized-hello":
            raise
    if mode in ("account-hello", "unauthorized-hello"):
        try:
            response = connection.recv(1)
        except (BrokenPipeError, ConnectionResetError):
            response = b""
        if response != b"":
            if mode == "account-hello":
                raise RuntimeError("gateway accepted an account-scoped hello over its nesting ceiling")
            raise RuntimeError("gateway admitted an unauthorized hello")
    else:
        length = struct.unpack(">I", read_exact(connection, 4))[0]
        response = json.loads(read_exact(connection, length))
        if response.get("type") != "hello":
            raise RuntimeError("gateway did not acknowledge a valid session hello")
        if mode == "hold":
            print("ready", flush=True)
            sys.stdin.buffer.read()
            connection.close()
elif mode == "initialization-timeout":
    if connection.recv(1) != b"":
        raise RuntimeError("gateway did not enforce the hello deadline")
elif mode == "malformed":
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(8)
    connection.connect(path)
    connection.sendall(struct.pack(">I", 65537))
    if connection.recv(1) != b"":
        raise RuntimeError("gateway accepted an oversized frame")
elif mode == "wrong-peer":
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(1)
    print("ready", flush=True)
    connection, _ = listener.accept()
    time.sleep(2)
    connection.close()
    listener.close()
    os.unlink(path)
else:
    raise RuntimeError("unknown probe mode")
