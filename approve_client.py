"""approve_client.py — WSS approval channel + E2EE helpers for the
InteractiveSudo root daemon (client side of approve_server.py).

The daemon owns exactly one persistent connection to the approval server
(wss://approve.<host>/ws/v1/client). Registration is authenticated with a
PSK (root-only file). Each request carries an ephemeral RSA-OAEP public key;
the approval page encrypts {password, secrets} with it (WebCrypto RSA-OAEP
+ AES-256-GCM), so the server relays ciphertext it can never read.

Threading model: one reader thread per connection (owned by ApproveChannel);
delivery to waiting request threads happens through per-request queues.
If the channel drops, pending registrations fail (no silent half-states).

Needs the `cryptography` package (python3-cryptography on Debian/Ubuntu).
"""

from __future__ import annotations

import base64
import json
import os
import queue
import socket
import ssl
import struct
import threading
import time
import urllib.parse

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "approve_client needs the 'cryptography' package "
        "(apt install python3-cryptography)") from exc

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x8, 0x9, 0xA
MAX_FRAME = 64 * 1024


class ChannelError(Exception):
    pass


# ---------------------------------------------------------------------------
# E2EE helpers (client side)
# ---------------------------------------------------------------------------


def generate_request_key() -> tuple[object, str]:
    """Ephemeral RSA-2048 keypair -> (private key object, SPKI-DER base64url)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, base64.urlsafe_b64encode(spki).decode().rstrip("=")


def open_payload(key, ek_b64: str, iv_b64: str, ct_b64: str) -> dict:
    """Decrypt {ek, iv, ct} as produced by the page (RSA-OAEP-256 + AES-256-GCM)."""
    def b64(s: str) -> bytes:
        s = s + "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    aes_key = key.decrypt(
        b64(ek_b64),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))
    try:
        plain = AESGCM(aes_key).decrypt(b64(iv_b64), b64(ct_b64), None)
    finally:
        aes_key = None  # drop reference; CPython frees the bytes object
    obj = json.loads(plain.decode("utf-8"))
    plain = None
    if not isinstance(obj, dict) or obj.get("v") != 1:
        raise ChannelError("unexpected payload version")
    return obj


# ---------------------------------------------------------------------------
# WebSocket framing (client side, must be masked)
# ---------------------------------------------------------------------------


class WsConn:
    def __init__(self, url: str, timeout: float = 20.0):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("wss", "ws"):
            raise ChannelError(f"unsupported scheme in {url!r}")
        self.tls = u.scheme == "wss"
        host = u.hostname
        port = u.port or (443 if self.tls else 80)
        self.path = u.path or "/"
        self.host_header = f"{host}:{port}" if u.port else host
        self.sock = socket.create_connection((host, port), timeout=timeout)
        if self.tls:
            ctx = ssl.create_default_context()
            self.sock = ctx.wrap_socket(self.sock, server_hostname=host)
        self.rfile = self.sock.makefile("rb")
        self.wfile = self.sock.makefile("wb")
        self._handshake()
        # The server pings every ~30 s; if nothing arrives for 150 s the
        # connection is a zombie -> raise and let the channel reconnect.
        self.sock.settimeout(150.0)

    def _handshake(self) -> None:
        import hashlib
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            "\r\n")
        self.wfile.write(req.encode())
        self.wfile.flush()
        status = self.rfile.readline().decode(errors="replace")
        if "101" not in status:
            raise ChannelError(f"ws handshake failed: {status.strip()!r}")
        accept = ""
        while True:
            line = self.rfile.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            k, _, v = line.decode(errors="replace").partition(":")
            if k.strip().lower() == "sec-websocket-accept":
                accept = v.strip()
        expect = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        if accept != expect:
            raise ChannelError("bad Sec-WebSocket-Accept")

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass

    # -- frames --

    def _readn(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.rfile.read(n - len(buf))
            if not chunk:
                raise ChannelError("connection closed")
            buf += chunk
        return buf

    def read_json(self):
        while True:
            hdr = self._readn(2)
            b0, b1 = hdr[0], hdr[1]
            opcode = b0 & 0x0F
            ln = b1 & 0x7F
            if b1 & 0x80:
                raise ChannelError("masked frame from server")
            if ln == 126:
                ln = struct.unpack(">H", self._readn(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._readn(8))[0]
            if ln > MAX_FRAME:
                raise ChannelError("frame too large")
            data = self._readn(ln) if ln else b""
            if opcode == OP_PING:
                self._frame(OP_PONG, data)
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CLOSE:
                raise ChannelError("server closed")
            if opcode == OP_TEXT:
                obj = json.loads(data.decode("utf-8"))
                if isinstance(obj, dict):
                    return obj
                raise ChannelError("non-object frame")

    def _frame(self, opcode: int, payload: bytes) -> None:
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.wfile.write(header + mask + masked)
        self.wfile.flush()

    def send_json(self, obj: dict) -> None:
        self._frame(OP_TEXT, json.dumps(obj, ensure_ascii=False).encode())


# ---------------------------------------------------------------------------
# channel
# ---------------------------------------------------------------------------


class PendingReg:
    def __init__(self) -> None:
        self.q: queue.Queue = queue.Queue()


class ApproveChannel(threading.Thread):
    """Persistent connection to the approval server.

    usage:
        ch = ApproveChannel(url, psk, client_label)
        ch.start()
        reg = ch.register(rid, command, reason, secret_names, ttl)
        -> returns (url_for_human, key) where key opens the E2EE payload
        ch.wait(rid, timeout) -> decision dicts:
            {"op": "decision", "decision": "approve", "scope": ...,
             "payload": {...}} | {"op": "decision", "decision": "deny"}
            | {"op": "expired"} | {"op": "channel_down"}
        ch.revoke(rid); ch.report(rid, status)
    """

    def __init__(self, url: str, psk: str, client_label: str = "interactivesudo",
                 log=print):
        super().__init__(daemon=True, name="approve-channel")
        self.url = url
        self.psk = psk
        self.label = client_label
        self.log = log
        self._lock = threading.Lock()
        self._conn: WsConn | None = None
        self._connected = threading.Event()
        self._pending: dict[str, PendingReg] = {}
        self._backoff = 2.0
        self._stop = threading.Event()

    # -- public --

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    def stop(self) -> None:
        self._stop.set()
        self._fail_all("stopping")

    def register(self, rid: str, command: str, reason: str,
                 secret_names: list[str], ttl_s: int,
                 connect_timeout: float = 10.0) -> tuple[str, object]:
        """Returns (approval_url_without_token_check, key). Raises ChannelError."""
        if not self._connected.wait(connect_timeout):
            raise ChannelError("approval channel not connected")
        key, spki = generate_request_key()
        reg = PendingReg()
        with self._lock:
            if not self._connected.is_set():
                raise ChannelError("approval channel not connected")
            self._pending[rid] = reg
        try:
            self._send({"op": "register", "id": rid, "command": command,
                        "reason": reason, "secrets": secret_names,
                        "pubkey": spki, "ttl": int(ttl_s),
                        "client": self.label})
        except ChannelError:
            with self._lock:
                self._pending.pop(rid, None)
            raise
        try:
            msg = reg.q.get(timeout=15)
        except queue.Empty:
            with self._lock:
                self._pending.pop(rid, None)
            raise ChannelError("no registration reply (channel lost)")
        if msg.get("op") != "registered":
            with self._lock:
                self._pending.pop(rid, None)
            raise ChannelError(f"registration refused: {msg}")
        base = urllib.parse.urlsplit(self.url)
        web = f"{base.scheme.replace('ws', 'http')}://{base.netloc}"
        url = f"{web}/#/r/{msg['token']}"
        return url, key

    def wait(self, rid: str, timeout: float):
        """Next decision-ish event for rid: decision / expired / channel_down.

        Blocks on the request's queue even if the entry is finalised
        concurrently; returns None on timeout, {"op": "gone"} if unknown.
        """
        reg = self._pending.get(rid)
        if reg is None:
            return {"op": "gone"}
        try:
            return reg.q.get(timeout=timeout)
        except queue.Empty:
            return None

    def revoke(self, rid: str) -> None:
        try:
            self._send({"op": "revoke", "id": rid})
        except ChannelError:
            pass
        self._pending.pop(rid, None)

    def done(self, rid: str) -> None:
        self._pending.pop(rid, None)

    def report(self, rid: str, status: str) -> None:
        try:
            self._send({"op": "result", "id": rid, "status": status})
        except ChannelError:
            pass

    # -- internals --

    def _send(self, obj: dict) -> None:
        with self._lock:
            conn = self._conn
            if conn is None:
                raise ChannelError("approval channel not connected")
            try:
                conn.send_json(obj)
            except Exception as exc:
                self._connected.clear()
                raise ChannelError(f"send failed: {exc}") from exc

    def _fail_all(self, why: str) -> None:
        self._connected.clear()
        with self._lock:
            con, self._conn = self._conn, None
            pend, self._pending = self._pending, {}
        if con:
            con.close()
        for rid, reg in pend.items():
            reg.q.put({"op": "channel_down", "detail": why})

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self._session()
                return  # graceful stop
            except Exception as exc:
                if self._stop.is_set():
                    return
                self._fail_all(str(exc))
                self.log(f"approve-channel: down ({exc}); retry in "
                         f"{self._backoff:.0f}s")
                if self._stop.wait(self._backoff):
                    return
                self._backoff = min(self._backoff * 2, 60.0)

    def _session(self) -> None:
        conn = WsConn(self.url)
        conn.send_json({"op": "hello", "psk": self.psk, "client": self.label})
        hello = conn.read_json()
        if hello.get("op") != "hello_ok":
            conn.close()
            raise ChannelError(f"hello rejected: {hello}")
        with self._lock:
            self._conn = conn
        self._connected.set()
        self._backoff = 2.0
        self.log(f"approve-channel: connected to {self.url}")
        while not self._stop.is_set():
            msg = conn.read_json()
            op = msg.get("op")
            rid = str(msg.get("id") or "")
            if op in ("decision", "expired", "registered", "register_err"):
                reg = self._pending.get(rid)
                if reg:
                    # keep the entry; the consumer calls done()/revoke()
                    reg.q.put(msg)
            # hello_ok handled above; further server ops ignored (forward-compat)
        self._fail_all("stopped")
        if self._stop.is_set():
            return
        raise ChannelError("stopped")
