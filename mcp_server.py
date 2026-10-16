#!/usr/bin/env python3
"""InteractiveSudoMCP — human-in-the-loop root for coding agents.

Architecture (v2)
-----------------
One file, two roles:

* Root daemon (`mcp_server.py daemon`, systemd service, stdlib only):
  owns the whole flow — denylist check, Matrix announcement, waiting for
  your 👍/👎, execution as root, history. Approval comes ONLY from Matrix
  (out-of-band from this machine): no local process — including the agent
  itself — can approve a request.

* MCP server (`mcp_server.py serve`, runs as you): thin forwarder. Sends
  requests to the daemon over a Unix socket and fires desktop
  notifications. Holds no secrets and no privileges.

MCP tools (stdio):
  sudo_run(command, reason, timeout_s)  Ask for approval, then run as root.
  sudo_status()                         Daemon health, pending, history.

CLI (user side):
  mcp_server.py status            Daemon status + recent history.
  mcp_server.py history [-n N]    Recent completed requests.
  mcp_server.py cancel  [id|last] Cancel a pending request.

How it works
------------
1. The agent calls sudo_run; the MCP server forwards it to the daemon.
2. The daemon checks the denylist, announces the request in Matrix, waits.
   At remind_after_s it sends a mention ping (push notification) and asks
   the client to re-fire the desktop notification.
3. You reply 👍 / yes to approve, 👎 / no to deny. Nothing else approves.
4. The daemon runs the command as root and returns exit code, stdout and
   stderr to the agent. If the requesting client disconnected meanwhile,
   the request is cancelled instead of executed.

Security model
--------------
- Approval only ever arrives via Matrix from your account; the bot's own
  messages are ignored. There are no local approval channels (no decision
  files, no CLI approve) — a compromised user account cannot self-approve.
- The deployed daemon code and its API key are root-owned. You edit the
  project copy and re-deploy with install.sh — a deliberate human sudo.
- Denylist substrings are refused without asking.
- Commands run as root with a minimal environment and cwd=/.
- If the requesting client disconnects before approval, the request is
  cancelled; a command that already started runs to completion.
- No passwords anywhere: the daemon is already root.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent

USER_DEFAULTS: dict = {
    "socket_path": "/run/interactivesudo/agent.sock",
    "desktop_notify": True,
}

DAEMON_DEFAULTS: dict = {
    "webhooker_url": "http://localhost:8080",
    "bot_name": "mybot",
    "api_key_file": "/etc/interactivesudo/api_key",
    "socket_path": "/run/interactivesudo/agent.sock",
    "socket_group": "operator",     # group allowed to talk to the daemon
    "state_dir": "/var/lib/interactivesudo",
    "poll_interval_s": 1.5,
    "wait_timeout_s": 600,          # how long to wait for 👍/👎
    "remind_after_s": 300,          # Matrix mention ping after this (0 = off)
    "remind_mxid": "",              # your MXID, mentioned so the ping pushes
    "command_timeout_s": 300,       # max runtime of the command itself
    "max_output_chars": 20000,      # stdout/stderr capture cap
    "max_pending": 5,               # refuse new requests beyond this many
    "denylist": [
        "mkfs",
        "dd if=",
        ":() {",
        "rm -rf /",
        "rm -rf /*",
        "> /dev/sd",
        "shred /dev/",
    ],
}

RUN_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

APPROVE_WORDS = {
    "yes", "y", "yep", "yeah", "ok", "okay", "approve", "approved", "go", "sure",
    "ja", "bitte", "klar", "👍", "👍🏼", "👍🏽",
}
DENY_WORDS = {
    "no", "n", "nope", "deny", "denied", "abort", "cancel", "stop",
    "nein", "abbrechen", "ablehnen", "ablehne", "👎", "👎🏼", "👎🏽",
}

# Reactions on the request/reminder message itself also decide.
REACTION_APPROVE = {"👍", "👍🏼", "👍🏽", "👍🏾", "👍🏿", "✅", "✔️"}
REACTION_DENY = {"👎", "👎🏼", "👎🏽", "👎🏾", "👎🏿", "❌", "✖️", "🚫"}


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_cfg(defaults: dict, env_var: str, default_path: str) -> dict:
    cfg = dict(defaults)
    path = Path(os.environ.get(env_var, "") or default_path)
    if path.exists():
        try:
            user_cfg = json.loads(path.read_text())
        except Exception as exc:
            raise SystemExit(f"config error in {path}: {exc}") from exc
        if not isinstance(user_cfg, dict):
            raise SystemExit(f"config error in {path}: top level must be an object")
        cfg.update(user_cfg)
    return cfg


def load_user_config() -> dict:
    return _load_cfg(USER_DEFAULTS, "SUDOMCP_CONFIG", str(PROJECT_DIR / "config.json"))


def load_daemon_config() -> dict:
    return _load_cfg(DAEMON_DEFAULTS, "SUDOMCP_DAEMON_CONFIG",
                     "/etc/interactivesudo/config.json")


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def normalize_command(command) -> list[str]:
    if isinstance(command, str):
        s = command.strip()
        if not s:
            raise ValueError("command must not be empty")
        return ["sh", "-c", s]
    if isinstance(command, (list, tuple)):
        if not command or not all(isinstance(x, str) and x.strip() for x in command):
            raise ValueError("command must be a non-empty list of strings")
        return [str(x) for x in command]
    raise ValueError("command must be a string or a list of strings")


def cmdline_of(argv: list[str]) -> str:
    if len(argv) >= 2 and argv[0] == "sh" and argv[1] == "-c":
        return argv[2]
    return " ".join(argv)


def parse_reply(raw: str) -> tuple[str | None, bool]:
    """Parse a human reply into (decision, had_extra_words).

    decision is "approve" | "deny" | None (not a decision).
    """
    text = (raw or "").strip().strip("`").strip()
    if not text:
        return None, False
    words = [w.lower().rstrip("!.") for w in text.split()]
    first = words[0]
    if first in APPROVE_WORDS:
        return "approve", len(text.split()) > 1
    if first in DENY_WORDS:
        return "deny", False
    # Fallback: a decision keyword anywhere in the message.
    if any(w in APPROVE_WORDS for w in words):
        return "approve", False
    if any(w in DENY_WORDS for w in words):
        return "deny", False
    return None, False


def cap(text: str | None, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [truncated {len(text) - limit} more chars]"


def desktop_notify(enabled: bool, title: str, body: str) -> None:
    if not enabled or not shutil.which("notify-send"):
        return
    try:
        subprocess.Popen(
            ["notify-send", "-u", "critical", title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def log(msg: str) -> None:
    print(f"[{utc_stamp()}] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# webhooker (Matrix) client — stdlib only, used by the daemon
# ---------------------------------------------------------------------------


class Webhooker:
    """Tiny stdlib client for MatrixWebhooker."""

    def __init__(self, cfg: dict):
        self.base = cfg["webhooker_url"].rstrip("/")
        key_path = Path(cfg["api_key_file"])
        if not key_path.exists():
            raise RuntimeError(f"api key file not found: {key_path}")
        self.key = key_path.read_text().strip()
        if not self.key:
            raise RuntimeError(f"api key file is empty: {key_path}")
        self.bot_user: str | None = None

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"X-API-Key": self.key,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())

    def health(self) -> dict:
        return self._req("GET", "/health")

    def me(self) -> dict:
        d = self._req("GET", "/me")
        self.bot_user = d.get("user")
        return d

    def send(self, text: str, html_body: str | None = None,
             msgtype: str = "m.text") -> dict:
        body: dict = {"text": text, "msgtype": msgtype}
        if html_body:
            body["html"] = html_body
        return self._req("POST", "/webhook", body)

    def send_notice(self, text: str) -> None:
        try:
            self.send(text, msgtype="m.notice")
        except Exception:
            pass

    def messages(self, room_id: str, limit: int = 25) -> list[dict]:
        q = urllib.parse.quote(room_id, safe="")
        return self._req("GET", f"/rooms/{q}/messages?limit={limit}").get("messages", [])


# ---------------------------------------------------------------------------
# root daemon
# ---------------------------------------------------------------------------


class ClientGone(Exception):
    """The requesting MCP client disconnected."""


class PendingRequest:
    def __init__(self, request_id: str, argv: list[str], reason: str,
                 timeout_s):
        self.id = request_id
        self.argv = argv
        self.reason = reason
        self.timeout_s = timeout_s
        self.ts = utc_stamp()
        self.cancel = threading.Event()


class Daemon:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.wh = Webhooker(cfg)
        self.state = Path(cfg["state_dir"])
        self.state.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.pending: dict[str, PendingRequest] = {}
        self.claimed: set[str] = set()   # Matrix event ids already acted on
        self.last_id: str | None = None

    # -- history ----------------------------------------------------------

    def append_history(self, entry: dict) -> None:
        p = self.state / "history.jsonl"
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        os.chmod(p, 0o600)

    def tail_history(self, n: int = 10) -> list[dict]:
        p = self.state / "history.jsonl"
        if not p.exists():
            return []
        out = []
        for line in p.read_text().splitlines()[-n:]:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
        return list(reversed(out))

    # -- Matrix -----------------------------------------------------------

    def announce_text(self, request_id: str, cmd: str,
                      reason: str) -> tuple[str, str]:
        esc = html.escape
        plain = (
            f"🔐 sudo request {request_id}\n"
            f"command: {cmd}\n"
            f"reason: {reason or '-'}\n"
            "React 👍 on this message to approve · 👎 to deny\n"
            "(or reply: yes / no)"
        )
        body = (
            f"🔐 <b>sudo request</b> <code>{esc(request_id)}</code><br>"
            f"command: <code>{esc(cmd)}</code><br>"
            f"<i>reason: {esc(reason or '-')}</i><br>"
            "React <b>👍</b> on this message to approve, <b>👎</b> to deny "
            "(or reply <b>yes</b>/<b>no</b>)."
        )
        return plain, body

    def send_reminder(self, p: PendingRequest) -> str | None:
        cfg = self.cfg
        esc = html.escape
        cmd = cmdline_of(p.argv)
        mxid = (cfg.get("remind_mxid") or "").strip()
        left = max(0, int(float(cfg["wait_timeout_s"])
                          - float(cfg.get("remind_after_s") or 0)))
        mention = f"{mxid} " if mxid else ""
        html_mention = (f'<a href="https://matrix.to/#/{esc(mxid)}">{esc(mxid)}</a> '
                        if mxid else "")
        try:
            resp = self.wh.send(
                f"🚨 {mention}sudo request {p.id} is still waiting: {cmd}\n"
                f"Reply 👍/yes or 👎/no — it expires in {left}s.",
                html_body=(
                    f"🚨 {html_mention}<b>sudo {esc(p.id)}</b> still waiting: "
                    f"<code>{esc(cmd)}</code><br>"
                    f"Reply 👍/👎 — expires in {left}s."
                ),
            )
            log(f"{p.id}: reminder ping sent")
            return resp.get("event_id")
        except Exception as exc:
            log(f"{p.id}: reminder ping failed: {exc}")
            return None

    def wait_matrix(self, p: PendingRequest, room_id: str, since_ts_ms: int,
                    deadline: float, remind_at: float | None, emit,
                    watch_ids: set[str]) -> tuple[str | None, str | None]:
        """Poll the room for a decision. Returns (decision, actor) or (None, None).

        Decisions: a text reply (yes/no/…), or a 👍/👎 reaction on one of
        watch_ids (this request's announcement or reminder message).
        Raises ClientGone if the requesting client disconnects (emit fails).
        """
        interval = float(self.cfg["poll_interval_s"])
        reminded = False
        while not p.cancel.is_set():
            try:
                for m in self.wh.messages(room_id, limit=25):
                    if m.get("sender") == self.wh.bot_user:
                        continue
                    ts = m.get("ts") or 0
                    if ts < since_ts_ms - 3000:
                        continue
                    if m.get("type") == "m.reaction":
                        if m.get("reacts_to") not in watch_ids:
                            continue  # reaction to some other message
                        rkey = (m.get("key") or "").strip()
                        if rkey in REACTION_APPROVE:
                            decision = "approve"
                        elif rkey in REACTION_DENY:
                            decision = "deny"
                        else:
                            continue
                    else:
                        decision, _ = parse_reply(m.get("body", ""))
                        if decision is None:
                            continue
                    # One decision event approves/denies exactly one request.
                    key = (m.get("event_id")
                           or f"{ts}:{m.get('sender')}:{m.get('body') or m.get('key')}")
                    with self.lock:
                        if key in self.claimed:
                            continue
                        self.claimed.add(key)
                        if len(self.claimed) > 500:
                            self.claimed.clear()
                    return decision, m.get("sender")
            except Exception:
                pass  # webhooker hiccup; retry on the next tick
            now = time.monotonic()
            if remind_at is not None and not reminded and now >= remind_at:
                reminded = True
                rid = self.send_reminder(p)
                if rid:
                    watch_ids.add(rid)
                emit({"event": "reminding", "request_id": p.id})
            if now >= deadline:
                return None, None
            time.sleep(interval)
        return "cancelled", None

    # -- main flow ----------------------------------------------------------

    def run_flow(self, p: PendingRequest, emit) -> dict:
        cfg = self.cfg
        t0 = time.monotonic()
        cmd = cmdline_of(p.argv)

        def result(extra: dict) -> dict:
            out = {"request_id": p.id, "command": cmd,
                   "duration_s": round(time.monotonic() - t0, 2)}
            out.update(extra)
            return out

        joined = " ".join(p.argv)
        for pattern in cfg.get("denylist") or []:
            if pattern and pattern in joined:
                log(f"{p.id}: refused by denylist pattern {pattern!r}")
                return result({
                    "ok": False, "status": "refused_by_policy",
                    "detail": f"command matches denylist pattern {pattern!r} — "
                              "denied without asking. Fix the command or adjust "
                              "the denylist in /etc/interactivesudo/config.json.",
                })

        try:
            me = self.wh.me()
            plain, body_html = self.announce_text(p.id, cmd, p.reason)
            sent = self.wh.send(plain, body_html)
            room_id = sent.get("room") or me.get("room")
            watch_ids = {sent.get("event_id")} - {None, ""}
            since_ts_ms = int(time.time() * 1000)
        except Exception as exc:
            return result({"ok": False, "status": "error",
                           "detail": f"cannot reach Matrix webhooker at "
                                     f"{cfg['webhooker_url']}: {exc}"})
        log(f"{p.id}: announced in {room_id}: {cmd}")
        emit({"event": "pending", "request_id": p.id, "command": cmd})

        deadline = time.monotonic() + float(cfg["wait_timeout_s"])
        remind_after = float(cfg.get("remind_after_s") or 0)
        remind_at = time.monotonic() + remind_after if remind_after > 0 else None
        try:
            decision, actor = self.wait_matrix(p, room_id, since_ts_ms,
                                               deadline, remind_at, emit,
                                               watch_ids)
        except ClientGone:
            p.cancel.set()
            decision, actor = "cancelled", None

        if decision == "cancelled" or p.cancel.is_set():
            self.append_history({"ts": utc_stamp(), "id": p.id, "command": cmd,
                                 "reason": p.reason, "status": "cancelled"})
            log(f"{p.id}: cancelled")
            return result({"ok": False, "status": "cancelled",
                           "detail": "request cancelled (client disconnected "
                                     "or 'cancel' command)"})
        if decision is None:
            self.append_history({"ts": utc_stamp(), "id": p.id, "command": cmd,
                                 "reason": p.reason, "status": "expired"})
            log(f"{p.id}: expired")
            return result({"ok": False, "status": "expired",
                           "detail": f"no decision within {cfg['wait_timeout_s']}s"})
        if decision != "approve":
            self.append_history({"ts": utc_stamp(), "id": p.id, "command": cmd,
                                 "reason": p.reason, "status": "denied",
                                 "approver": actor})
            self.wh.send_notice(f"🚫 sudo {p.id} denied by {actor or 'user'}")
            log(f"{p.id}: denied by {actor}")
            return result({"ok": False, "status": "denied", "approver": actor})

        # approved — execute as root
        log(f"{p.id}: approved by {actor}, running as uid={os.getuid()}")
        timeout = int(p.timeout_s or cfg["command_timeout_s"])
        try:
            proc = subprocess.run(p.argv, capture_output=True, text=True,
                                  timeout=timeout, cwd="/", env=RUN_ENV)
        except subprocess.TimeoutExpired:
            self.append_history({"ts": utc_stamp(), "id": p.id, "command": cmd,
                                 "reason": p.reason, "status": "timeout",
                                 "approver": actor})
            self.wh.send_notice(f"⏱ sudo {p.id} timed out after {timeout}s")
            return result({"ok": False, "status": "timeout",
                           "detail": f"command timed out after {timeout}s",
                           "approver": actor})
        except Exception as exc:
            return result({"ok": False, "status": "error", "detail": str(exc),
                           "approver": actor})

        ok = proc.returncode == 0
        self.append_history({"ts": utc_stamp(), "id": p.id, "command": cmd,
                             "reason": p.reason, "status": "done",
                             "exit_code": proc.returncode, "approver": actor,
                             "source": "matrix"})
        self.wh.send_notice(
            f"{'✅' if ok else '❌'} sudo {p.id} finished: exit {proc.returncode}")
        log(f"{p.id}: done, exit {proc.returncode}")
        return result({
            "ok": ok, "status": "done", "approver": actor,
            "exit_code": proc.returncode,
            "stdout": cap(proc.stdout, int(cfg["max_output_chars"])),
            "stderr": cap(proc.stderr, int(cfg["max_output_chars"])),
        })

    # -- ops ----------------------------------------------------------------

    def status(self) -> dict:
        with self.lock:
            pend = [{"id": p.id, "command": cmdline_of(p.argv),
                     "reason": p.reason, "ts": p.ts}
                    for p in self.pending.values()]
        wh = {"url": self.cfg["webhooker_url"], "ok": False}
        try:
            me = self.wh.me()
            wh.update({"ok": True, "bot": me.get("bot"),
                       "bot_user": me.get("user"), "room": me.get("room")})
        except Exception as exc:
            wh["error"] = str(exc)
        return {"running_as_uid": os.getuid(),
                "socket": self.cfg["socket_path"],
                "pending": pend,
                "recent_history": self.tail_history(5),
                "webhooker": wh}

    def cancel(self, rid: str) -> dict:
        if rid == "last" or not rid:
            rid = self.last_id or ""
        with self.lock:
            p = self.pending.get(rid)
        if p is None:
            return {"ok": False, "status": "not_found",
                    "detail": f"no pending request {rid!r}"}
        p.cancel.set()
        return {"ok": True, "status": "cancelled", "request_id": rid}


class Handler(socketserver.StreamRequestHandler):
    timeout = 60

    def reply(self, obj: dict) -> None:
        self.wfile.write((json.dumps(obj) + "\n").encode())
        self.wfile.flush()

    def emit(self, event: dict) -> None:
        """Stream an event; raise ClientGone if the client is gone."""
        try:
            self.reply(event)
        except (BrokenPipeError, OSError):
            raise ClientGone()

    def handle(self) -> None:
        app: Daemon = self.server.app
        line = self.rfile.readline()
        if not line:
            return
        try:
            msg = json.loads(line)
            op = msg.get("op")
        except Exception:
            self.reply({"result": {"ok": False, "status": "error",
                                   "detail": "malformed request"}})
            return
        if op == "run":
            self.handle_run(app, msg)
        elif op == "status":
            self.reply({"result": app.status()})
        elif op == "history":
            self.reply({"result": {"history": app.tail_history(
                int(msg.get("n") or 10))}})
        elif op == "cancel":
            self.reply({"result": app.cancel(str(msg.get("id") or "last"))})
        else:
            self.reply({"result": {"ok": False, "status": "error",
                                   "detail": f"unknown op {op!r}"}})

    def handle_run(self, app: Daemon, msg: dict) -> None:
        try:
            argv = normalize_command(msg.get("command"))
        except ValueError as exc:
            self.reply({"result": {"ok": False, "status": "error",
                                   "detail": str(exc)}})
            return
        request_id = ("s-" + datetime.now().strftime("%Y%m%d-%H%M%S")
                      + "-" + os.urandom(2).hex())
        p = PendingRequest(request_id, argv, str(msg.get("reason") or ""),
                           msg.get("timeout_s"))
        with app.lock:
            if len(app.pending) >= int(app.cfg.get("max_pending") or 5):
                self.reply({"result": {
                    "ok": False, "status": "error",
                    "detail": f"too many pending requests "
                              f"(>= {app.cfg.get('max_pending')})"}})
                return
            app.pending[request_id] = p
            app.last_id = request_id
        try:
            res = app.run_flow(p, self.emit)
        except ClientGone:
            p.cancel.set()
            res = None  # nobody left to talk to
        finally:
            with app.lock:
                app.pending.pop(request_id, None)
        if res is not None:
            self.reply({"result": res})


class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def serve_daemon() -> None:
    cfg = load_daemon_config()
    app = Daemon(cfg)
    path = Path(cfg["socket_path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.connect(str(path))
            probe.close()
            raise SystemExit(f"another daemon is already listening on {path}")
        except (ConnectionRefusedError, OSError):
            path.unlink()
    srv = UnixServer(str(path), Handler)
    srv.app = app
    os.chmod(str(path), 0o660)
    grp = (cfg.get("socket_group") or "").strip()
    if grp:
        import grp as grpmod
        try:
            os.chown(str(path), 0, grpmod.getgrnam(grp).gr_gid)
        except Exception as exc:
            log(f"warning: could not chown socket to group {grp}: {exc}")
    log(f"daemon up: uid={os.getuid()} socket={path} "
        f"webhooker={cfg['webhooker_url']}")
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# user-side client (MCP forwarder + CLI)
# ---------------------------------------------------------------------------


def daemon_call(cfg: dict, msg: dict, on_event=None) -> dict:
    path = cfg["socket_path"]
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as exc:
        return {"ok": False, "status": "error",
                "detail": f"cannot reach the interactivesudo daemon at {path}: "
                          f"{exc} — is 'systemctl start interactivesudo' done?"}
    try:
        f = s.makefile("rw", encoding="utf-8")
        f.write(json.dumps(msg) + "\n")
        f.flush()
        while True:
            line = f.readline()
            if not line:
                return {"ok": False, "status": "error",
                        "detail": "daemon closed the connection"}
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if "event" in obj:
                if on_event is not None:
                    try:
                        on_event(obj)
                    except Exception:
                        pass
                continue
            return obj.get("result") or {"ok": False, "status": "error",
                                         "detail": "malformed daemon reply"}
    finally:
        s.close()


def tool_sudo_run(command, reason: str = "", timeout_s=None) -> dict:
    cfg = load_user_config()
    try:
        argv = normalize_command(command)
    except ValueError as exc:
        return {"ok": False, "status": "error", "detail": str(exc)}

    def on_event(e: dict) -> None:
        if not cfg.get("desktop_notify", True):
            return
        if e.get("event") == "pending":
            desktop_notify(True, "InteractiveSudo — approval needed",
                           f"{e.get('request_id')}: {e.get('command')}")
        elif e.get("event") == "reminding":
            desktop_notify(True, "InteractiveSudo — still waiting",
                           f"{e.get('request_id')}: reply 👍/👎 in Matrix")

    return daemon_call(cfg, {"op": "run", "command": argv,
                             "reason": reason or "", "timeout_s": timeout_s},
                       on_event)


def tool_sudo_status() -> dict:
    return daemon_call(load_user_config(), {"op": "status"})


# ---------------------------------------------------------------------------
# MCP server (user-side)
# ---------------------------------------------------------------------------


def serve() -> None:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(
        "interactive-sudo",
        instructions=(
            "Human-in-the-loop root. Use sudo_run for ANY command that needs "
            "root. The user is asked in Matrix and must react 👍 on the "
            "request message (or reply yes) to approve; 👎/no denies. "
            "Nothing else counts. There are no passwords — a root daemon "
            "executes the command after approval. Put a short human-readable "
            "reason in every call. Never put secrets in 'reason'."
        ),
    )

    @mcp.tool()
    def sudo_run(command: str | list[str], reason: str = "",
                 timeout_s: int | None = None) -> dict:
        """Run a command as root after interactive human approval.

        The request is announced in the user's Matrix room; the user reacts
        👍 on the request message (or replies yes) to approve, 👎/no to
        deny. If the user does not decide within the timeout, the request
        expires. Returns ok, exit_code, stdout, stderr.

        Args:
            command: argv list (preferred) or shell string.
            reason: short human explanation shown to the approver.
            timeout_s: max runtime of the command (default from config).
        """
        return tool_sudo_run(command, reason=reason, timeout_s=timeout_s)

    @mcp.tool()
    def sudo_status() -> dict:
        """Daemon health, pending requests, recent history."""
        return tool_sudo_status()

    mcp.run(transport="stdio")


# ---------------------------------------------------------------------------
# CLI (user side)
# ---------------------------------------------------------------------------


def cmd_status(_args) -> int:
    cfg = load_user_config()
    print(f"socket  : {cfg['socket_path']}")
    st = daemon_call(cfg, {"op": "status"})
    if st.get("status") == "error":
        print(st["detail"])
        return 1
    print(f"daemon  : uid={st.get('running_as_uid')} socket={st.get('socket')}")
    wh = st.get("webhooker", {})
    if wh.get("ok"):
        print(f"webhooker: OK  bot={wh.get('bot')} user={wh.get('bot_user')} "
              f"room={wh.get('room')}")
    else:
        print(f"webhooker: FAIL ({wh.get('error')})")
    pend = st.get("pending") or []
    if pend:
        print("pending requests:")
        for r in pend:
            print(f"  {r['id']}  {r['command']}  (since {r.get('ts')})")
    else:
        print("pending requests: none")
    hist = st.get("recent_history") or []
    if hist:
        print("recent:")
        for h in hist:
            print(f"  {h.get('ts')}  {h.get('id')}  {h.get('status')}  "
                  f"exit={h.get('exit_code')}  {h.get('command', '')[:70]}")
    else:
        print("recent: (none yet)")
    return 0


def cmd_history(args) -> int:
    res = daemon_call(load_user_config(), {"op": "history", "n": args.n})
    for h in res.get("history") or []:
        print(json.dumps(h, ensure_ascii=False))
    return 0


def cmd_cancel(args) -> int:
    res = daemon_call(load_user_config(), {"op": "cancel", "id": args.id})
    if res.get("ok"):
        print(f"cancelled {res.get('request_id')}")
        return 0
    print(res.get("detail") or json.dumps(res))
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mcp_server.py",
        description="InteractiveSudoMCP — human-in-the-loop root for agents.",
    )
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the MCP stdio server (default)")
    sub.add_parser("daemon", help="run the root daemon (used by systemd)")
    sub.add_parser("status", help="daemon status + recent history")
    p_hist = sub.add_parser("history", help="show recent requests")
    p_hist.add_argument("-n", type=int, default=10)
    p_can = sub.add_parser("cancel", help="cancel a pending request")
    p_can.add_argument("id", nargs="?", default="last")
    args = parser.parse_args()
    args.cmd = args.cmd or "serve"
    handlers = {
        "serve": lambda _a: serve(),
        "daemon": lambda _a: serve_daemon(),
        "status": cmd_status,
        "history": cmd_history,
        "cancel": cmd_cancel,
    }
    handlers[args.cmd](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
