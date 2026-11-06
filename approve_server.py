#!/usr/bin/env python3
"""approved — blind approval relay for InteractiveSudoMCP (runs on the server).

The client (your PC) connects out over WSS and registers a pending sudo
request; this service only ever sees opaque metadata and an E2EE blob it
cannot read. The human opens https://approve.<host>/#/r/<token> (token in the
URL *fragment*: never sent to this server in any request line, referer or
access log), reads the command, types their password; the browser encrypts
with the request's ephemeral RSA key and POSTs it back. The server relays the
ciphertext to the already-open WSS connection. Passwords never touch disk,
logs, or this process's readable memory (RSA-OAEP ciphertext only).

Security properties (v3 design, agreed 2026-11-04):
- Registration requires the PSK (single shared secret, root-only files).
- Token: 256-bit random, single-use, short TTL, constant-time compare,
  stored only as sha256; logs carry truncated hashes only.
- GET only displays (link unfurlers do GET); POST carries the decision.
- Rate limits per token and per IP; generic 404/410 for anything invalid.
- TLS is terminated by nginx; this listens on 127.0.0.1 only.
- Stdlib only. State is in-memory only (restart drops pending requests).

CLI:  approve_server.py [--config /etc/approved/config.json]
Config JSON:
{
  "bind": "127.0.0.1", "port": 8095, "psk": "<registration key>",
  "ttl_s": 300, "same_cmd_minutes": 10, "max_attempts": 3,
  "page_title": "approve.example.com"
}
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import struct
import sys
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "3.1"

# --- WS opcode constants (RFC 6455 subset: text frames, ping/pong, close) ---
OP_TEXT, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x8, 0x9, 0xA
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME = 64 * 1024

DEFAULTS = {
    "bind": "127.0.0.1",
    "port": 8095,
    "psk": "",
    "ttl_s": 300,
    "same_cmd_minutes": 10,
    "max_attempts": 3,
    "page_title": "sudo approval",
    "max_token_hits": 60,
    "ping_interval_s": 30,
    "dead_after_s": 95,
    "result_ttl_s": 900,
    "exec_hold_s": 900,
}


def sha256_b64(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def b64url_decode(s: str) -> bytes:
    """base64url with optional padding (the page/client strip '=' )."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def short(h: str) -> str:
    return h[:8]


def log(msg: str) -> None:
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {msg}",
          file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# WebSocket framing (shared minimal implementation)
# ---------------------------------------------------------------------------


class WsError(Exception):
    pass


def ws_read_frame(rfile, max_size: int = MAX_FRAME):
    """Read one frame -> (opcode, payload bytes). Raises WsError on break."""
    def readn(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = rfile.read(n - len(buf))
            if not chunk:
                raise WsError("connection closed")
            buf += chunk
        return buf

    hdr = readn(2)
    b0, b1 = hdr[0], hdr[1]
    opcode = b0 & 0x0F
    masked = b1 & 0x80
    ln = b1 & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", readn(2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", readn(8))[0]
    if ln > max_size:
        raise WsError("frame too large")
    mask = readn(4) if masked else None
    data = readn(ln) if ln else b""
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return opcode, data


def ws_write_frame(wfile, opcode: int, payload: bytes, mask: bool = False) -> None:
    header = bytes([0x80 | opcode])
    n = len(payload)
    mb = 0x80 if mask else 0
    if n < 126:
        header += bytes([mb | n])
    elif n < 65536:
        header += bytes([mb | 126]) + struct.pack(">H", n)
    else:
        header += bytes([mb | 127]) + struct.pack(">Q", n)
    if mask:
        m = os.urandom(4)
        payload = bytes(b ^ m[i % 4] for i, b in enumerate(payload))
        header += m
    wfile.write(header + payload)
    wfile.flush()


def ws_send_text(wfile, text: str, mask: bool = False) -> None:
    ws_write_frame(wfile, OP_TEXT, text.encode(), mask)


def ws_send_json(wfile, obj: dict, mask: bool = False) -> None:
    ws_send_text(wfile, json.dumps(obj, ensure_ascii=False), mask)


# ---------------------------------------------------------------------------
# pending-request registry (in-memory only)
# ---------------------------------------------------------------------------


class Entry:
    __slots__ = ("rid", "token_hash", "meta", "pubkey", "created", "expires",
                 "state", "hits", "attempts", "conn", "tombstone", "result")

    def __init__(self, rid, token_hash, meta, pubkey, ttl):
        self.rid = rid
        self.token_hash = token_hash
        self.meta = meta            # command/reason/secret names (display only)
        self.pubkey = pubkey        # SPKI base64 (client's ephemeral RSA key)
        self.created = time.time()
        self.expires = self.created + ttl
        self.state = "pending"      # pending|sent|ok|auth_failed|denied|expired
        self.hits = 0
        self.attempts = 0
        self.conn = None
        self.tombstone = 0.0
        # opaque sealed result from the daemon ({ek,iv,ct}) — relay never
        # sees its content, only stores and forwards it
        self.result = None


class Registry:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.by_rid: dict[str, Entry] = {}
        self.conns: dict[int, "ClientConn"] = {}

    def create(self, rid, token, meta, pubkey, ttl) -> Entry:
        e = Entry(rid, sha256_b64(token), meta, pubkey, ttl)
        with self.lock:
            self.by_rid[rid] = e
        return e

    def find(self, token: str):
        th = sha256_b64(token or "")
        now = time.time()
        with self.lock:
            for e in self.by_rid.values():
                if hmac.compare_digest(e.token_hash, th):
                    if e.expires < now and e.state in ("pending", "sent",
                                                       "auth_failed"):
                        return e, "expired"
                    return e, e.state
        return None, None

    def drop(self, rid: str, state: str = "ok",
             tombstone_s: float = 120.0) -> None:
        """Keep a tombstone so the page can poll a final state."""
        with self.lock:
            e = self.by_rid.get(rid)
        if e:
            e.state = state
            e.tombstone = time.time() + tombstone_s


REGISTRY: Registry  # set in main


class RateLimiter:
    """Token bucket per key (IP or per-token hit counter)."""

    def __init__(self, rate_per_min: float, burst: int):
        self.rate = rate_per_min / 60.0
        self.burst = float(burst)
        self.lock = threading.Lock()
        self.bucket: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            tokens, ts = self.bucket.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - ts) * self.rate)
            if tokens < 1:
                self.bucket[key] = (tokens, now)
                return False
            self.bucket[key] = (tokens - 1, now)
            return True


API_LIMIT = RateLimiter(rate_per_min=30, burst=20)
POST_LIMIT = RateLimiter(rate_per_min=12, burst=6)


# ---------------------------------------------------------------------------
# client WSS sessions (one per connected daemon)
# ---------------------------------------------------------------------------


class ClientConn:
    def __init__(self, cid: int, rfile, wfile, peer, raw_sock):
        self.cid = cid
        self.rfile = rfile
        self.wfile = wfile
        self.raw_sock = raw_sock
        self.peer = peer
        self.alive = True
        self.last_seen = time.time()
        self.write_lock = threading.Lock()

    def send(self, obj: dict) -> bool:
        if not self.alive:
            return False
        try:
            with self.write_lock:
                ws_send_json(self.wfile, obj)
            return True
        except Exception:
            self.alive = False
            return False

    def recv(self) -> dict:
        """Next text frame; pings answered in-line (write-locked)."""
        while True:
            opcode, payload = ws_read_frame(self.rfile)
            self.last_seen = time.time()
            if opcode == OP_PING:
                try:
                    with self.write_lock:
                        ws_write_frame(self.wfile, OP_PONG, payload)
                except Exception:
                    raise WsError("pong failed")
                continue
            if opcode == OP_PONG:
                return {"op": "pong"}
            if opcode == OP_CLOSE:
                raise WsError("peer sent close")
            if opcode == OP_TEXT:
                try:
                    obj = json.loads(payload.decode("utf-8"))
                except Exception as exc:
                    raise WsError("bad json frame") from exc
                if isinstance(obj, dict):
                    return obj
                raise WsError("non-object frame")

    def abort(self) -> None:
        self.alive = False
        try:
            with self.write_lock:
                ws_write_frame(self.wfile, OP_CLOSE, b"bye")
        except Exception:
            pass
        try:
            self.raw_sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass


CONNECTIONS: dict[int, ClientConn] = {}
CONN_LOCK = threading.Lock()
CID_SEQ = 0


def push_to_conn(conn: ClientConn | None, obj: dict) -> bool:
    if conn is None:
        return False
    return conn.send(obj)


# ---------------------------------------------------------------------------
# HTTP + WS request handler
# ---------------------------------------------------------------------------

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
RID_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")


class Handler(BaseHTTPRequestHandler):
    server_version = "approved/" + VERSION
    protocol_version = "HTTP/1.1"

    # ---- plumbing -------------------------------------------------------

    def log_message(self, fmt: str, *args) -> None:  # noqa: N802
        pass  # replaced by explicit hashed logs below

    def client_ip(self) -> str:
        fwd = self.headers.get("X-Forwarded-For")
        if fwd:
            return fwd.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "?"

    def _send(self, code: int, body: bytes, ctype: str,
              extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src "
                         "'self'; connect-src 'self'; form-action 'self'; "
                         "base-uri 'none'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json; charset=utf-8")

    def send_generic_404(self) -> None:
        self.send_json(404, {"error": "not_found"})

    def bearer(self) -> str:
        h = self.headers.get("Authorization", "")
        return h[7:].strip() if h.startswith("Bearer ") else ""

    def read_body(self, limit: int = 32 * 1024) -> bytes | None:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if n <= 0 or n > limit:
            return None
        data = self.rfile.read(n)
        return data if len(data) == n else None

    # ---- static ---------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        ip = self.client_ip()
        if not API_LIMIT.allow(ip):
            self.send_json(429, {"error": "rate_limited"})
            return
        path = urllib.parse.urlsplit(self.path).path
        if path == "/ws/v1/client":
            self.handle_ws_upgrade()
            return
        if path in ("/", "/index.html"):
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/app.js":
            self._send(200, APP_JS.encode("utf-8"),
                       "text/javascript; charset=utf-8",
                       {"Cache-Control": "no-cache"})
            return
        if path == "/style.css":
            self._send(200, APP_CSS.encode("utf-8"), "text/css; charset=utf-8",
                       {"Cache-Control": "no-cache"})
            return
        if path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /\n", "text/plain")
            return
        if path == "/healthz":
            self.send_json(200, {"ok": True, "version": VERSION})
            return
        if path == "/api/v1/request":
            self.api_meta()
            return
        if path == "/api/v1/request/status":
            self.api_status()
            return
        if path == "/api/v1/request/result":
            self.api_result()
            return
        self.send_generic_404()

    # ---- API: meta for the page -----------------------------------------

    def api_meta(self) -> None:
        token = self.bearer()
        e, state = REGISTRY.find(token)
        if e is None or state in ("expired", "ok", "denied"):
            self.send_generic_404()
            return
        e.hits += 1
        if e.hits > int(REGISTRY.cfg["max_token_hits"]):
            REGISTRY.drop(e.rid, "expired")
            log(f"hits-exceeded tok={short(e.token_hash)}")
            self.send_generic_404()
            return
        if e.conn is None or not e.conn.alive:
            self.send_generic_404()  # client gone -> nothing to approve
            return
        log(f"view tok={short(e.token_hash)} rid={e.rid}")
        self.send_json(200, {
            "id": e.rid,
            "command": e.meta.get("command", ""),
            "reason": e.meta.get("reason", ""),
            "client": e.meta.get("client", ""),
            "secrets": e.meta.get("secrets", []),
            "pubkey": e.pubkey,
            "expires_in": max(0, int(e.expires - time.time())),
            "same_cmd_minutes": int(REGISTRY.cfg["same_cmd_minutes"]),
            "title": REGISTRY.cfg["page_title"],
        })

    def api_status(self) -> None:
        token = self.bearer()
        e, state = REGISTRY.find(token)
        if e is None or state == "expired":
            self.send_generic_404()
            return
        self.send_json(200, {"state": state,
                             "expires_in": max(0, int(e.expires - time.time())),
                             "has_result": bool(e.result)})

    def api_result(self) -> None:
        """Serve the sealed execution result (exit code + output) to the
        page. The relay never sees the cleartext."""
        token = self.bearer()
        e, state = REGISTRY.find(token)
        if e is None or not e.result:
            self.send_generic_404()
            return
        log(f"result-served tok={short(e.token_hash)} rid={e.rid}")
        self.send_json(200, {"state": state, **e.result})

    # ---- API: decision ----------------------------------------------------

    def api_decision(self) -> None:
        ip = self.client_ip()
        if not POST_LIMIT.allow(ip):
            self.send_json(429, {"error": "rate_limited"})
            return
        token = self.bearer()
        e, state = REGISTRY.find(token)
        if e is None or state in ("expired", "ok", "denied"):
            self.send_generic_404()
            return
        body = self.read_body()
        if body is None:
            self.send_json(400, {"error": "bad_request"})
            return
        try:
            msg = json.loads(body.decode("utf-8"))
        except Exception:
            self.send_json(400, {"error": "bad_request"})
            return
        e.hits += 1
        if e.hits > int(REGISTRY.cfg["max_token_hits"]):
            REGISTRY.drop(e.rid, "expired")
            self.send_generic_404()
            return
        decision = msg.get("decision")
        if decision == "deny":
            REGISTRY.drop(e.rid, "denied")
            push_to_conn(e.conn, {"op": "decision", "id": e.rid,
                                  "decision": "deny"})
            log(f"deny-page tok={short(e.token_hash)} rid={e.rid}")
            self.send_json(200, {"ok": True, "state": "denied"})
            return
        if decision != "approve":
            self.send_json(400, {"error": "bad_request"})
            return
        if state not in ("pending", "auth_failed"):
            self.send_json(409, {"error": "try_later", "state": state})
            return
        if e.attempts >= int(REGISTRY.cfg["max_attempts"]):
            REGISTRY.drop(e.rid, "expired")
            log(f"attempts-exceeded tok={short(e.token_hash)} rid={e.rid}")
            self.send_json(409, {"error": "too_many_attempts"})
            return
        scope = msg.get("scope") or "once"
        if scope != "once" and not re.fullmatch(
                rf"same:{int(REGISTRY.cfg['same_cmd_minutes'])}", str(scope)):
            scope = "once"
        blob = msg.get("payload") or {}
        ek, iv, ct = blob.get("ek"), blob.get("iv"), blob.get("ct")
        if not (isinstance(ek, str) and isinstance(iv, str)
                and isinstance(ct, str) and len(ek) <= 1024 and len(ct) <= 8192):
            self.send_json(400, {"error": "bad_request"})
            return
        for v in (ek, iv, ct):
            try:
                b64url_decode(v)
            except Exception:
                self.send_json(400, {"error": "bad_request"})
                return
        if e.conn is None or not e.conn.alive:
            REGISTRY.drop(e.rid, "expired")
            self.send_generic_404()
            return
        e.attempts += 1
        e.state = "sent"
        ok = push_to_conn(e.conn, {"op": "decision", "id": e.rid,
                                   "decision": "approve", "scope": scope,
                                   "payload": {"ek": ek, "iv": iv, "ct": ct,
                                               "alg": "RSA-OAEP-256+AES-256-GCM"}})
        if not ok:
            REGISTRY.drop(e.rid, "expired")
            self.send_generic_404()
            return
        log(f"approve-page tok={short(e.token_hash)} rid={e.rid} scope={scope}")
        self.send_json(200, {"ok": True, "state": "sent"})

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/v1/request/decision":
            self.api_decision()
        else:
            self.send_generic_404()

    # ---- WS client sessions ----------------------------------------------

    def handle_ws_upgrade(self) -> None:
        key = self.headers.get("Sec-WebSocket-Key", "")
        if (self.headers.get("Upgrade", "").lower() != "websocket" or not key):
            self.send_json(400, {"error": "websocket required"})
            return
        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.close_connection = True
        serve_client_ws(self)


def serve_client_ws(handler: Handler) -> None:
    """Full lifecycle of one daemon WSS session (on the handler thread)."""
    global CID_SEQ
    with CONN_LOCK:
        CID_SEQ += 1
        cid = CID_SEQ
    conn = ClientConn(cid, handler.rfile, handler.wfile, handler.client_ip(),
                      handler.connection)
    try:
        hello = conn.recv()
    except Exception:
        return
    psk = REGISTRY.cfg.get("psk") or ""
    if (not psk or hello.get("op") != "hello"
            or not hmac.compare_digest(str(hello.get("psk", "")), psk)):
        log(f"ws auth-denied from {conn.peer}")
        conn.send({"op": "hello_err", "error": "psk mismatch"})
        conn.abort()
        return
    conn.send({"op": "hello_ok", "ttl_s": int(REGISTRY.cfg["ttl_s"]),
               "same_cmd_minutes": int(REGISTRY.cfg["same_cmd_minutes"])})
    log(f"ws client-hello from {conn.peer} ({hello.get('client', '?')})")
    with CONN_LOCK:
        CONNECTIONS[cid] = conn

    stop = threading.Event()

    def pinger() -> None:
        while not stop.wait(float(REGISTRY.cfg["ping_interval_s"])):
            if not conn.alive:
                return
            if time.time() - conn.last_seen > float(REGISTRY.cfg["dead_after_s"]):
                log(f"ws dead {conn.peer}")
                conn.abort()
                return
            try:
                with conn.write_lock:
                    ws_write_frame(conn.wfile, OP_PING, b"ka")
            except Exception:
                conn.alive = False
                return

    threading.Thread(target=pinger, daemon=True).start()
    try:
        while conn.alive:
            msg = conn.recv()
            op = msg.get("op")
            if op == "register":
                handle_register(conn, msg)
            elif op == "revoke":
                handle_revoke(conn, msg)
            elif op == "result":
                handle_result(conn, msg)
            # unknown ops ignored (forward-compat)
    except Exception:
        pass
    finally:
        stop.set()
        conn.alive = False
        with CONN_LOCK:
            CONNECTIONS.pop(cid, None)
        # requests bound to a dead channel can never be approved
        with REGISTRY.lock:
            for e in list(REGISTRY.by_rid.values()):
                if (e.conn is conn
                        and e.state in ("pending", "sent", "auth_failed")):
                    e.state = "expired"
                    e.tombstone = time.time() + 120
        log(f"ws client-left {conn.peer} (pending dropped)")


def handle_register(conn: ClientConn, msg: dict) -> None:
    rid = str(msg.get("id") or "")
    cmd = str(msg.get("command") or "")
    if not RID_RE.fullmatch(rid) or not cmd or len(cmd) > 8000:
        conn.send({"op": "register_err", "id": rid, "error": "bad_request"})
        return
    secrets_names = msg.get("secrets") or []
    if not isinstance(secrets_names, list):
        secrets_names = []
    secrets_names = [s for s in map(str, secrets_names[:12])
                     if NAME_RE.fullmatch(s)]
    pubkey = str(msg.get("pubkey") or "")
    try:
        raw = b64url_decode(pubkey)
        if len(raw) < 200 or len(raw) > 800:
            raise ValueError
    except Exception:
        conn.send({"op": "register_err", "id": rid, "error": "bad_pubkey"})
        return
    ttl = min(max(int(msg.get("ttl") or REGISTRY.cfg["ttl_s"]), 30),
              3600)
    token = secrets.token_urlsafe(32)
    meta = {
        "command": cmd[:8000],
        "reason": str(msg.get("reason") or "")[:2000],
        "client": str(msg.get("client") or "")[:120],
        "secrets": secrets_names,
    }
    e = REGISTRY.create(rid, token, meta, pubkey, ttl)
    e.conn = conn
    conn.send({"op": "registered", "id": rid, "token": token,
               "expires_at": e.expires})
    log(f"register rid={rid} tok={short(sha256_b64(token))} ttl={ttl}s")


def handle_revoke(conn: ClientConn, msg: dict) -> None:
    rid = str(msg.get("id") or "")
    with REGISTRY.lock:
        e = REGISTRY.by_rid.get(rid)
    if (e is not None and e.conn is conn
            and e.state in ("pending", "sent", "auth_failed")):
        e.state = "denied"
        e.tombstone = time.time() + 120
        log(f"revoked-by-client rid={rid} tok={short(e.token_hash)}")


def handle_result(conn: ClientConn, msg: dict) -> None:
    rid = str(msg.get("id") or "")
    status = str(msg.get("status") or "?")[:40]
    payload = msg.get("payload")
    with REGISTRY.lock:
        e = REGISTRY.by_rid.get(rid)
    if e is None or e.conn is not conn:
        return
    if status == "executing":
        hold = float(REGISTRY.cfg.get("exec_hold_s", 900))
        e.expires = max(e.expires, time.time() + hold)
        log(f"executing rid={rid} hold=+{int(hold)}s")
    elif status == "auth_failed" and \
            e.attempts < int(REGISTRY.cfg["max_attempts"]):
        with REGISTRY.lock:
            e.state = "auth_failed"
        log(f"auth-failed rid={rid} tok={short(e.token_hash)}")
    elif status in ("done", "denied", "cancelled", "error", "timeout"):
        sealed = isinstance(payload, dict) and payload.get("ct")
        if sealed:
            e.result = {k: str(payload.get(k) or "")[:4096]
                        for k in ("ek", "iv", "ct")}
            REGISTRY.drop(rid, "ok" if status == "done" else status,
                          tombstone_s=float(REGISTRY.cfg.get("result_ttl_s",
                                                             900)))
        else:
            REGISTRY.drop(rid, "ok" if status == "done" else status)
        log(f"result rid={rid} status={status}"
            + (" sealed" if sealed else ""))


def reaper() -> None:
    while True:
        time.sleep(2)
        now = time.time()
        expired = []
        with REGISTRY.lock:
            for e in list(REGISTRY.by_rid.values()):
                if (e.expires < now
                        and e.state in ("pending", "sent", "auth_failed")):
                    e.state = "expired"
                    e.tombstone = now + 120
                    expired.append(e)
                elif e.tombstone and e.tombstone < now:
                    REGISTRY.by_rid.pop(e.rid, None)
        for e in expired:
            push_to_conn(e.conn, {"op": "expired", "id": e.rid})
            log(f"expired rid={e.rid} tok={short(e.token_hash)}")


# ---------------------------------------------------------------------------
# static page (self-contained, no CDN, German UI)
# ---------------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>sudo-Freigabe</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<main id="card">
  <h1>&#128272; sudo-Freigabe</h1>
  <p id="hint">Lade Anfrage&hellip;</p>

  <section id="req" hidden>
    <p class="meta"><span id="rid"></span> &middot; <span id="client"></span>
      &middot; l&auml;uft ab in <span id="count">-</span></p>
    <h2>Befehl</h2>
    <pre id="cmd"></pre>
    <h2>Grund</h2>
    <p id="reason"></p>
    <div id="secrethint"></div>
    <form id="form" autocomplete="off">
      <div id="errbox" class="errbox" hidden>
        <span id="errtxt"></span>
        <button id="errclose" type="button" aria-label="schlie&szlig;en">&times;</button>
      </div>
      <label>Sudo-Passwort
        <input id="pw" type="password" autocomplete="new-password" required>
      </label>
      <div id="secrets"></div>
      <label>Freiscope
        <select id="scope"></select>
      </label>
      <div class="row">
        <button id="go" type="submit">&#128273; Freigeben</button>
        <button id="no" type="button" class="danger">Ablehnen</button>
      </div>
    </form>
  </section>

  <p id="status" role="status"></p>
  <details id="resbox" hidden>
    <summary id="ressum">Ergebnis</summary>
    <pre id="resout"></pre>
  </details>
</main>
<script src="/app.js"></script>
</body>
</html>
"""

APP_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font: 16px/1.5 system-ui, sans-serif; margin: 0; min-height: 100vh;
       display: flex; align-items: center; justify-content: center;
       background: #12141a; color: #e8eaf0; }
#card { background: #1b1e27; border: 1px solid #2c3040; border-radius: 14px;
        padding: 28px 30px; width: min(680px, 94vw); }
h1 { font-size: 1.25rem; margin: 0 0 12px; }
h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .06em;
     color: #98a0b5; margin: 18px 0 6px; }
pre { background: #10121a; border: 1px solid #2c3040; border-radius: 8px;
      padding: 12px; white-space: pre-wrap; word-break: break-word;
      font: .9rem/1.45 ui-monospace, monospace; }
.meta { color: #98a0b5; font-size: .85rem; }
label { display: block; margin: 14px 0 0; font-size: .9rem; color: #c6cbdb; }
input, select { width: 100%; margin-top: 4px; padding: 10px;
      border-radius: 8px; border: 1px solid #3a405a; background: #10121a;
      color: inherit; font: inherit; }
.row { display: flex; gap: 10px; margin-top: 20px; }
button { flex: 1; padding: 12px; border-radius: 10px; border: 0;
      font: inherit; font-weight: 600; cursor: pointer;
      background: #4f7cff; color: #fff; }
button:disabled { opacity: .5; cursor: wait; }
button.danger { background: #3a405a; }
#status { min-height: 1.4em; margin: 16px 0 0; font-weight: 600; }
#status.err { color: #ff9a9a; background: rgba(255,90,90,.15);
border: 1px solid rgba(255,110,110,.55); border-radius: 8px;
padding: 8px 10px; }
#status.ok { color: #6de08a; }
.errbox { display: flex; justify-content: space-between; align-items: center;
gap: 8px; background: rgba(255,90,90,.15); border: 1px solid
rgba(255,110,110,.55); border-radius: 8px; padding: 8px 10px;
margin: 0 0 12px; color: #ff9a9a; font-weight: 600; }
.errbox[hidden] { display: none; }
.errbox button { background: none; border: none; color: inherit;
font-size: 1.25em; line-height: 1; padding: 0 4px; cursor: pointer; }
#secrethint { font-size: .85rem; color: #ffb86c; margin-top: 10px; }
#resbox { margin-top: 14px; border: 1px solid #3a405a; border-radius: 8px;
padding: 8px 12px; }
#resbox summary { cursor: pointer; font-weight: 600; }
#resout { white-space: pre-wrap; word-break: break-all; max-height: 420px;
overflow: auto; font-size: .82rem; background: rgba(127,127,127,.12);
padding: .6em .8em; border-radius: 6px; margin: .6em 0 0; }
"""

APP_JS = """'use strict';
const $ = (id) => document.getElementById(id);
const B64 = {
  urlToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s); const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
  bytesToB64(b) {
    let s = ''; const u = new Uint8Array(b);
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  },
};
let token = null, meta = null, pollTimer = null, tickTimer = null;

function setStatus(msg, cls) { const el = $('status');
  el.textContent = msg || ''; el.className = cls || '';
  if (cls === 'err') el.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }

function showFormErr(msg) { const b = $('errbox');
  $('errtxt').textContent = msg; b.hidden = false;
  b.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
function clearFormErr() { $('errbox').hidden = true; }
$('errclose').onclick = clearFormErr;

function stopTimers() { if (pollTimer) clearInterval(pollTimer);
  if (tickTimer) clearInterval(tickTimer); pollTimer = tickTimer = null; }

function dead(msg) { stopTimers(); $('req').hidden = true;
  $('hint').hidden = true; setStatus(msg, 'err');
  showResult().catch(() => {}); }

async function api(path, opts) {
  opts = opts || {}; opts.headers = Object.assign(
    { 'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json' }, opts.headers || {});
  const r = await fetch(path, opts);
  if (r.status === 404) return { gone: true };
  if (r.status === 429) return { limited: true };
  return await r.json().catch(() => ({ gone: true }));
}

function tick() {
  if (!meta) return;
  meta.expires_in -= 1;
  const m = Math.floor(Math.max(0, meta.expires_in) / 60);
  const s = Math.max(0, meta.expires_in) % 60;
  $('count').textContent = m + ':' + String(s).padStart(2, '0');
  if (meta.expires_in <= 0) dead('Diese Anfrage ist abgelaufen.');
}

async function load() {
  const m = (location.hash || '').match(/^#\\/r\\/([A-Za-z0-9_-]{20,100})$/);
  if (!m) { $('hint').textContent =
    'Diese Seite zeigt Freigaben an. \\u00d6ffne den Link aus deiner ' +
    'Matrix-Nachricht (der Freigabe-Code steht nach dem # in der URL).';
    return; }
  token = m[1];
  history.replaceState(null, '', location.pathname);
  const r = await api('/api/v1/request');
  if (r.gone) return dead('Anfrage nicht (mehr) g\\u00fcltig \\u2014 ' +
    'abgelaufen, bereits beantwortet oder abgelehnt.');
  if (r.limited) return dead('Zu viele Anfragen \\u2014 bitte kurz warten.');
  meta = r;
  $('hint').hidden = true; $('req').hidden = false;
  $('rid').textContent = 'Anfrage ' + meta.id;
  $('client').textContent = meta.client || '';
  $('cmd').textContent = meta.command;
  $('reason').textContent = meta.reason || '\\u2014';
  document.title = 'sudo-Freigabe ' + meta.id;
  if (meta.secrets && meta.secrets.length) {
    $('secrethint').textContent = 'Dieser Befehl erh\\u00e4lt als ' +
      'Umgebungsvariablen: ' + meta.secrets.join(', ') +
      ' \\u2014 Werte werden verschl\\u00fcsselt \\u00fcbertragen und ' +
      'nur zur Ausführung verwendet.';
    for (const n of meta.secrets) {
      const l = document.createElement('label');
      l.textContent = 'Geheimnis $' + n;
      const i = document.createElement('input');
      i.type = 'password'; i.autocomplete = 'new-password';
      i.dataset.name = n; l.appendChild(i); $('secrets').appendChild(l);
    }
  }
  const sel = $('scope');
  const o1 = document.createElement('option');
  o1.value = 'once'; o1.textContent = 'Nur dieses eine Mal';
  sel.appendChild(o1);
  if (meta.same_cmd_minutes > 0) {
    const o2 = document.createElement('option');
    o2.value = 'same:' + meta.same_cmd_minutes;
    o2.textContent = 'Diesen Befehl nochmal f\\u00fcr ' +
      meta.same_cmd_minutes + ' Minuten';
    sel.appendChild(o2);
  }
  tick(); tickTimer = setInterval(tick, 1000);
  $('form').addEventListener('submit', approve);
  $('no').addEventListener('click', denyPage);
}

async function approve(ev) {
  ev.preventDefault();
  clearFormErr();
  $('go').disabled = true; $('no').disabled = true;
  setStatus('Verschl\\u00fcssele \\u2026');
  try {
    const pub = await crypto.subtle.importKey('spki',
      B64.urlToBytes(meta.pubkey),
      { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const aesKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    let result_ek = '';
    try {
      const rk = await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, hash: 'SHA-256',
          publicExponent: new Uint8Array([1, 0, 1]) }, true,
        ['encrypt', 'decrypt']);
      result_ek = B64.bytesToB64(
        await crypto.subtle.exportKey('spki', rk.publicKey));
      localStorage.setItem('isudo_rk_' + token,
        JSON.stringify(await crypto.subtle.exportKey('jwk', rk.privateKey)));
    } catch (e) { /* result channel optional */ }
    const pw = $('pw').value;
    const secrets = {};
    document.querySelectorAll('#secrets input').forEach(i => {
      if (i.value) secrets[i.dataset.name] = i.value;
    });
    const plain = new TextEncoder().encode(JSON.stringify(
      { v: 1, id: meta.id, password: pw, secrets, scope: $('scope').value,
        result_ek: result_ek, ts: Math.floor(Date.now() / 1000) }));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, plain);
    const raw = await crypto.subtle.exportKey('raw', aesKey);
    const ek = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw);
    $('pw').value = '';
    document.querySelectorAll('#secrets input').forEach(i => i.value = '');
    setStatus('Sende an deinen Rechner \\u2026');
    const r = await api('/api/v1/request/decision', { method: 'POST',
      body: JSON.stringify({ decision: 'approve', scope: $('scope').value,
        payload: { ek: B64.bytesToB64(ek), iv: B64.bytesToB64(iv),
                   ct: B64.bytesToB64(ct) } }) });
    if (r.gone) return dead('Anfrage nicht (mehr) g\\u00fcltig.');
    if (r.error === 'too_many_attempts')
      return dead('Zu viele Fehlversuche \\u2014 Anfrage beendet.');
    poll();
  } catch (e) {
    showFormErr('Fehler: ' + e);
    $('go').disabled = false; $('no').disabled = false;
  }
}

async function denyPage() {
  $('go').disabled = true; $('no').disabled = true;
  const r = await api('/api/v1/request/decision',
    { method: 'POST', body: JSON.stringify({ decision: 'deny' }) });
  stopTimers(); $('req').hidden = true;
  setStatus(r.gone ? 'Anfrage war schon erledigt.'
                   : 'Abgelehnt. Der Befehl wurde nicht ausgef\\u00fchrt.', 'ok');
}

async function showResult() {
  if (showResult.done) return; showResult.done = true;
  const r = await api('/api/v1/request/result');
  if (!r || r.gone || !r.ct) return;
  $('resbox').hidden = false;
  const enc = localStorage.getItem('isudo_rk_' + token);
  if (!enc) { $('ressum').textContent =
    'Ergebnis vorhanden \\u2014 zum Entschl\\u00fcsseln hier im Browser ' +
    'freigeben (Schl\\u00fcssel liegt lokal).'; return; }
  try {
    const prv = await crypto.subtle.importKey('jwk', JSON.parse(enc),
      { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    const aesRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, prv,
      B64.urlToBytes(r.ek));
    const aesKey = await crypto.subtle.importKey('raw', aesRaw,
      { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: B64.urlToBytes(r.iv) }, aesKey,
      B64.urlToBytes(r.ct));
    const d = JSON.parse(new TextDecoder().decode(plain));
    $('ressum').textContent =
      (d.status === 'done' ? 'Ausgef\\u00fchrt' : String(d.status || 'Beendet')) +
      (d.exit_code === null || d.exit_code === undefined
        ? '' : ' \\u00b7 exit ' + d.exit_code);
    let txt = d.stdout || '';
    if (d.stderr) txt += (txt ? '\\n' : '') + '[stderr]\\n' + d.stderr;
    $('resout').textContent = txt || '(keine Ausgabe)';
  } catch (e) {
    $('ressum').textContent = 'Ergebnis konnte nicht entschl\\u00fcsselt ' +
      'werden (anderer Browser?)';
  }
}

function poll() {
  setStatus('Warte auf Ausf\\u00fchrung \\u2026');
  if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
  const finish = (msg) => { stopTimers(); $('req').hidden = true;
    setStatus(msg, 'ok'); showResult().catch(() => {}); };
  pollTimer = setInterval(async () => {
    const r = await api('/api/v1/request/status');
    if (r.gone) { stopTimers(); $('req').hidden = true;
      setStatus('Anfrage nicht (mehr) g\\u00fcltig.', 'err');
      showResult().catch(() => {}); return; }
    if (r.state === 'ok') finish('\\u2713 Ausgef\\u00fchrt.');
    else if (r.state === 'auth_failed') {
      $('go').disabled = false; $('no').disabled = false;
      if (document.activeElement !== $('pw')) {
        $('pw').focus({ preventScroll: true }); $('pw').select(); }
      showFormErr('Passwort falsch \\u2014 bitte erneut versuchen.'); }
    else if (r.state === 'denied') return dead('Abgelehnt.');
    else if (r.state === 'done') finish('\\u2713 Ausgef\\u00fchrt.');
  }, 1500);
}

load();
"""


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/etc/approved/config.json")
    args = ap.parse_args()
    cfg = dict(DEFAULTS)
    try:
        with open(args.config, "r", encoding="utf-8") as fh:
            cfg.update(json.load(fh))
    except FileNotFoundError:
        log(f"config not found: {args.config}")
        return 1
    if not cfg.get("psk"):
        log("refusing to start: psk not configured")
        return 1
    global REGISTRY
    REGISTRY = Registry(cfg)
    threading.Thread(target=reaper, daemon=True).start()

    class Server(ThreadingHTTPServer):
        daemon_threads = True

    srv = Server((cfg["bind"], int(cfg["port"])), Handler)
    log(f"approved {VERSION} listening on {cfg['bind']}:{cfg['port']} "
        f"(tls via nginx)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
