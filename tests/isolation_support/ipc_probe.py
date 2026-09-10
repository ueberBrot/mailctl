"""Small adversarial Unix-socket probes for the native qualification."""

import ctypes
import os
import json
import socket
import struct
import sys
import time

mode, path = sys.argv[1:]

# <sys/un.h> on macOS defines these for getsockopt(2).
SOL_LOCAL = 0
LOCAL_PEEREPID = 3

def read_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected gateway EOF")
        data.extend(chunk)
    return bytes(data)

def peer_credentials(connection):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.getpeereid.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)
    ]
    libc.getsockopt.argtypes = [
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)
    ]
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    if libc.getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise OSError(ctypes.get_errno(), "getpeereid")
    pid = ctypes.c_int()
    length = ctypes.c_uint(ctypes.sizeof(pid))
    if libc.getsockopt(
        connection.fileno(), SOL_LOCAL, LOCAL_PEEREPID, ctypes.byref(pid), ctypes.byref(length)
    ) != 0:
        raise OSError(ctypes.get_errno(), "getsockopt(LOCAL_PEEREPID)")
    if length.value != ctypes.sizeof(pid):
        raise RuntimeError("unexpected LOCAL_PEEREPID size")
    if pid.value <= 0:
        raise RuntimeError("gateway peer did not report a positive process ID")
    return {"uid": uid.value, "pid": pid.value}

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
elif mode == "peer":
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(3)
    connection.connect(path)
    json.dump(peer_credentials(connection), sys.stdout)
    sys.stdout.write("\n")
    connection.close()
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
