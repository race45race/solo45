"""A tiny ZeroMQ SUB client: just enough ZMTP 3.0 (NULL security) to receive Bitcoin Core's
zmqpubhashblock notifications without the pyzmq library.

Standard library only.
"""
import socket
import struct

MORE, LONG, COMMAND = 0x01, 0x02, 0x04


class ZmqSub:
    def __init__(self, host, port, topic=b"hashblock", timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        # greeting: signature, version 3.0, NULL mechanism, not a server, filler (64 bytes)
        self.sock.sendall(b"\xff" + bytes(8) + b"\x7f" + b"\x03\x00" + b"NULL".ljust(20, b"\x00") + b"\x00" + bytes(31))
        peer = self._read(64)
        if peer[0] != 0xFF or peer[9] != 0x7F or peer[10] < 3:
            raise ConnectionError("the other side doesn't speak ZMTP 3")
        props = b"\x0bSocket-Type" + struct.pack(">I", 3) + b"SUB"
        self._send(b"\x05READY" + props, COMMAND)
        flags, _ = self._frame()
        if not flags & COMMAND:
            raise ConnectionError("expected the publisher's READY")
        self._send(b"\x01" + topic)  # subscribe (ZMTP 3.0 style: a message starting with 1)
        self.sock.settimeout(None)  # from here on, wait for blocks as long as it takes

    def _read(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("the node closed the ZMQ connection")
            buf += chunk
        return buf

    def _send(self, body, flags=0):
        if len(body) > 255:
            self.sock.sendall(bytes([flags | LONG]) + struct.pack(">Q", len(body)) + body)
        else:
            self.sock.sendall(bytes([flags, len(body)]) + body)

    def _frame(self):
        flags = self._read(1)[0]
        size = struct.unpack(">Q", self._read(8))[0] if flags & LONG else self._read(1)[0]
        return flags, self._read(size)

    def recv(self):
        """The next message as a list of frames, e.g. [b"hashblock", <32-byte hash>, <4-byte sequence>]."""
        parts = []
        while True:
            flags, body = self._frame()
            if flags & COMMAND:
                continue  # a command such as PING, not part of a message
            parts.append(body)
            if not flags & MORE:
                return parts

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
