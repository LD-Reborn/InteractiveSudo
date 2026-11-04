#!/usr/bin/env python3
"""InteractiveSudoMCP — human-in-the-loop root for coding agents.

Architecture (v3)
-----------------
Two roles + an approval relay:

* Root daemon (`mcp_server.py daemon`, systemd service): owns the whole
  flow — denylist check, registration with the approval server over a
  persistent WSS channel, Matrix announcement with a one-time HTTPS
  approval link, waiting for the decision, password check, execution as
  root, history. Needs `cryptography` + `approve_client.py`.

* Approval relay (`approve_server.py`, runs on your public host behind
  nginx/TLS): a blind relay. It registers endpoints only while a request
  is pending, serves the approval page, relays E2EE ciphertext to the
  already-open WSS channel. Registration requires a PSK.

* MCP server (`mcp_server.py serve`, runs as you): thin forwarder over a
  Unix socket + desktop notifications. No secrets, no privileges.

MCP tools (stdio):
  sudo_run(command, reason, timeout_s, secret_vars)  Ask, then run as root.
  sudo_status()                                      Daemon health, grants.

CLI (user side):
  mcp_server.py status            Daemon status + recent history.
  mcp_server.py history [-n N]    Recent completed requests.
  mcp_server.py cancel  [id|last] Cancel a pending request.
  mcp_server.py revoke  [list|all|<id>]  Manage "same command" grants.

How it works (URL approval, the default)
----------------------------------------
1. The agent calls sudo_run; the MCP server forwards it to the daemon.
2. The daemon registers the request with the approval server over WSS
   (PSK-authenticated) together with an ephemeral RSA public key and gets
   back a single-use token. Matrix gets only a short notice + link:
   https://approve.<host>/#/r/<token> (the token is a URL *fragment*: it
   never reaches any server log, referer or link-preview crawler).
3. You open the link, read command + reason + which named secrets the
   command will receive, type your sudo password, and approve. The
   browser encrypts {password, secrets} with the request's ephemeral key
   (RSA-OAEP + AES-256-GCM); the relay forwards ciphertext it cannot read.
4. The daemon verifies your password (chpasswd -c, shadow/PAM — never
   stored, never logged, scrubbed from command output) and executes.
5. 👍/yes in Matrix are IGNORED for approval (the old channel's single-
   factor weakness); 👎/no on the message stays a deny-only emergency
   brake. Scope options: "once" or "same command for N minutes".

Legacy (pure-Matrix 👍/👎) mode still runs when approve_url is empty; set
fallback_matrix_approve to use it when the relay is unreachable.

Security model
--------------
- Approval requires possession (single-use URL token, short TTL, single
  endpoint registration, rate limits) AND knowledge (your sudo password,
  verified via chpasswd -c). The bot's own messages are ignored; there are
  no local approval channels — a compromised user account cannot approve.
- The password and named secrets travel only inside per-request E2EE
  blobs; they never enter chat, agent context, the relay, or logs, and
  are scrubbed from captured stdout/stderr.
- The deployed daemon code is root-owned (install.sh). Denylist substrings
  are refused without asking. Commands run as root, minimal env, cwd=/.
- If the requesting client disconnects or you 👎, the request is cancelled
  before execution; a running command always runs to completion.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
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
    "socket_group": "operator",    # group allowed to talk to the daemon
    "state_dir": "/var/lib/interactivesudo",
    "poll_interval_s": 1.5,
    "wait_timeout_s": 600,          # how long to wait for 👍/👎
    "remind_after_s": 300,          # Matrix mention ping after this (0 = off)
    "remind_mxid": "",              # your MXID, mentioned so the ping pushes
    "command_timeout_s": 300,       # max runtime of the command itself
    "max_output_chars": 20000,      # stdout/stderr capture cap
    "max_pending": 5,               # refuse new requests beyond this many
    # --- v3 URL approval (approve_server.py relay) ---
    "approve_url": "",              # e.g. wss://approve.example.com/ws/v1/client
    "approve_psk_file": "/etc/interactivesudo/approve_psk",
    "approve_user": "operator",     # account whose password approves
    "approve_ttl_s": 300,           # link lifetime; also the wait deadline
    "approve_remind_s": 180,        # Matrix mention ping (0 = off)
    "fallback_matrix_approve": False,  # allow legacy 👍 if relay is down
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
# Keys are normalized: U+FE0F (emoji variation selector, sent by e.g.
# Element as "👍️") is stripped before matching.
REACTION_APPROVE = {"👍", "👍🏼", "👍🏽", "👍🏾", "👍🏿", "✅", "✔"}
REACTION_DENY = {"👎", "👎🏼", "👎🏽", "👎🏾", "👎🏿", "❌", "✖", "🚫"}


def norm_emoji(key: str) -> str:
    return key.strip().replace("\ufe0f", "")


SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
SECRET_DETECT_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]{0,40})?\}?")


def normalize_secret_names(names, argv: list[str] | None = None) -> list[str]:
    """Declared + auto-detected ($VAR / ${VAR}) secret placeholders."""
    out: list[str] = []

    def add(n: object) -> None:
        n = str(n or "").strip()
        if SECRET_NAME_RE.fullmatch(n) and n not in out:
            out.append(n)

    if isinstance(names, (list, tuple)):
        for n in names:
            add(n)
    for a in (argv or []):
        if isinstance(a, str) and "$" in a:
            for m in SECRET_DETECT_RE.finditer(a):
                if m.group(1):
                    add(m.group(1))
    return out[:12]


def verify_login_password(user: str, password: str) -> bool:
    """Check a login password against shadow/PAM via chpasswd -c.

    Runs as root only; the password goes through stdin (never argv, never
    stored). Any nonzero exit or odd input is treated as "wrong".
    """
    if not password or not user or len(password) > 1024:
        return False
    if any(c in password for c in "\n\r\x00") or any(
            c in user for c in "\n\r\x00:"):
        return False
    try:
        proc = subprocess.run(
            ["chpasswd", "-c"], input=f"{user}:{password}\n",
            capture_output=True, text=True, timeout=15, env=RUN_ENV)
        return proc.returncode == 0
    except Exception:
        return False


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
    text = (raw or "").strip().strip("`").strip().replace("\ufe0f", "")
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
                 timeout_s, secret_names: list[str] | None = None):
        self.id = request_id
        self.argv = argv
        self.reason = reason
        self.timeout_s = timeout_s
        self.secret_names = secret_names or []
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
        # v3: approval relay channel
        self.channel = None
        self.channel_error: str | None = None
        if (cfg.get("approve_url") or "").strip():
            try:
                import approve_client
                psk = Path(cfg["approve_psk_file"]).read_text().strip()
                if not psk:
                    raise RuntimeError(f"empty psk file: "
                                       f"{cfg['approve_psk_file']}")
                self.channel = approve_client.ApproveChannel(
                    cfg["approve_url"].strip(), psk,
                    client_label=f"interactivesudo@{socket.gethostname()}",
                    log=log)
                self.channel.start()
            except Exception as exc:
                self.channel = None
                self.channel_error = str(exc)
                log(f"approve channel unavailable: {exc}")
        # "same command for N minutes" grants (memory-only, root daemon)
        self.grants: dict[str, dict] = {}

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
                    watch_ids: set[str], deny_only: bool = False,
                    approve_hint=None, remind=None
                    ) -> tuple[str | None, str | None]:
        """Poll the room for a decision. Returns (decision, actor) or (None, None).

        Decisions: a text reply (yes/no/…), or a 👍/👎 reaction on one of
        watch_ids (this request's announcement or reminder message).
        In deny_only mode (URL approval) approvals via chat are refused —
        only 👎/no acts, and approve_hint() may explain where to go instead.
        Raises ClientGone if the requesting client disconnects (emit fails).
        """
        interval = float(self.cfg["poll_interval_s"])
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
                        rkey = norm_emoji(m.get("key") or "")
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
                    if deny_only and decision == "approve":
                        if not getattr(p, "hinted", False) \
                                and approve_hint is not None:
                            p.hinted = True
                            try:
                                approve_hint()
                            except Exception:
                                pass
                        continue  # chat cannot approve URL-mode requests
                    return decision, m.get("sender")
            except Exception:
                pass  # webhooker hiccup; retry on the next tick
            now = time.monotonic()
            if (remind_at is not None and not getattr(p, "reminded", False)
                    and now >= remind_at):
                p.reminded = True
                rid = (remind or self.send_reminder)(p)
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

        # v3: URL approval via the relay is the default path.
        if self.channel is not None:
            return self.run_flow_url(p, emit, result, cmd)
        if (cfg.get("approve_url") or "").strip():
            if not cfg.get("fallback_matrix_approve"):
                return result({
                    "ok": False, "status": "channel_down",
                    "detail": "approval relay unavailable"
                              + (f" ({self.channel_error})"
                                 if self.channel_error else "")
                              + " and fallback_matrix_approve is off — "
                                "no approval channel is active."})
            log(f"{p.id}: relay unavailable — legacy Matrix approval")
        return self.run_flow_matrix(p, emit, result, cmd)

    # -- execution ----------------------------------------------------------

    def execute(self, p: PendingRequest, result, secrets_d: dict,
                approver: str, password: str = "", scope: str = "once",
                source: str = "url") -> dict:
        cfg = self.cfg
        cmd = cmdline_of(p.argv)
        timeout = int(p.timeout_s or cfg["command_timeout_s"])
        env = dict(RUN_ENV)
        env.update(secrets_d)
        log(f"{p.id}: approved ({approver}), running as uid={os.getuid()}")
        try:
            proc = subprocess.run(p.argv, capture_output=True, text=True,
                                  timeout=timeout, cwd="/", env=env)
        except subprocess.TimeoutExpired:
            self.append_history({"ts": utc_stamp(), "id": p.id, "command": cmd,
                                 "reason": p.reason, "status": "timeout",
                                 "approver": approver, "scope": scope,
                                 "source": source})
            self.wh.send_notice(f"⏱ sudo {p.id} timed out after {timeout}s")
            return result({"ok": False, "status": "timeout",
                           "detail": f"command timed out after {timeout}s",
                           "approver": approver})
        except Exception as exc:
            return result({"ok": False, "status": "error", "detail": str(exc),
                           "approver": approver})

        ok = proc.returncode == 0
        self.append_history({"ts": utc_stamp(), "id": p.id, "command": cmd,
                             "reason": p.reason, "status": "done",
                             "exit_code": proc.returncode, "approver": approver,
                             "scope": scope, "source": source})
        self.wh.send_notice(
            f"{'✅' if ok else '❌'} sudo {p.id} finished: exit "
            f"{proc.returncode}")
        log(f"{p.id}: done, exit {proc.returncode}")
        limit = int(cfg["max_output_chars"])
        return result({
            "ok": ok, "status": "done", "approver": approver, "scope": scope,
            "exit_code": proc.returncode,
            "stdout": self.scrub(cap(proc.stdout, limit), secrets_d, password),
            "stderr": self.scrub(cap(proc.stderr, limit), secrets_d, password),
        })

    # -- "same command for N minutes" grants --------------------------------

    @staticmethod
    def grant_key(argv: list[str]) -> str:
        return hashlib.sha256(json.dumps(list(argv)).encode()).hexdigest()

    def sweep_grants(self) -> None:
        now = time.time()
        with self.lock:
            for k in [k for k, g in self.grants.items()
                      if g["expires"] < now]:
                self.grants.pop(k, None)

    def grant_list(self) -> list[dict]:
        self.sweep_grants()
        with self.lock:
            return [{"id": k[:8], "command": g["label"],
                     "expires_in_s": max(0, int(g["expires"] - time.time()))}
                    for k, g in self.grants.items()]

    def grant_revoke(self, arg: str) -> dict:
        self.sweep_grants()
        arg = (arg or "all").strip()
        with self.lock:
            if arg == "all":
                n = len(self.grants)
                self.grants.clear()
                return {"ok": True, "revoked": n}
            hits = [k for k in self.grants if k.startswith(arg)]
            if len(hits) != 1:
                return {"ok": False,
                        "detail": f"grant {arg!r} not unique/unknown "
                                  f"({len(hits)} hits)"}
            self.grants.pop(hits[0], None)
            return {"ok": True, "revoked": 1, "grant": hits[0][:8]}

    def store_grant(self, gkey: str, password: str, secrets_d: dict,
                    minutes: int, label: str) -> None:
        with self.lock:
            self.grants[gkey] = {"password": password,
                                 "secrets": dict(secrets_d),
                                 "expires": time.time() + minutes * 60,
                                 "label": label[:300]}
        log(f"grant stored for {minutes} min: {label[:80]!r}")

    @staticmethod
    def scrub(text: str, secrets_d: dict, password: str) -> str:
        """Remove injected secrets/password from captured output."""
        vals = [password] + [v for v in secrets_d.values()
                             if isinstance(v, str)]
        for v in sorted({v for v in vals if v and len(v) >= 3},
                        key=len, reverse=True):
            text = text.replace(v, "[REDACTED]")
        return text

    # -- URL approval (v3) ---------------------------------------------------

    def announce_url(self, p: PendingRequest, url: str,
                     ttl: int) -> tuple[str, str]:
        esc = html.escape
        plain = (
            f"🔐 sudo request {p.id} — approval required\n"
            f"{url}\n"
            "The command + reason will only be shown on the approval page; "
            "after that, your password (E2EE, not stored).\n"
            f"Expiry: {int(ttl / 60)} min · 👎 on this message = deny · "
            "👍 is ignored here"
        )
        body = (
            f"🔐 <b>sudo request</b> <code>{esc(p.id)}</code><br>"
            f'<a href="{esc(url)}"><b>Approve in browser</b></a><br>'
            f"<i>command + reason only on the page · password required "
            f"(E2EE) · expires in {int(ttl / 60)} min</i><br>"
            "👎 on this message = deny · 👍 is ignored here."
        )
        return plain, body

    def run_flow_url(self, p: PendingRequest, emit, result, cmd: str) -> dict:
        cfg = self.cfg
        ch = self.channel
        ttl = int(cfg.get("approve_ttl_s") or 300)

        # "this command again" grant → password check, no new approval round
        gkey = self.grant_key(p.argv)
        self.sweep_grants()
        with self.lock:
            grant = self.grants.get(gkey)
        if grant:
            if verify_login_password(cfg["approve_user"], grant["password"]):
                log(f"{p.id}: active grant matches — running without "
                    f"a new approval")
                return self.execute(p, result, grant["secrets"],
                                    approver="stored grant",
                                    password=grant["password"],
                                    scope="grant", source="grant")
            log(f"{p.id}: grant password no longer valid — dropping grant")
            with self.lock:
                self.grants.pop(gkey, None)

        try:
            url, key = ch.register(p.id, cmd, p.reason, p.secret_names, ttl)
        except Exception as exc:
            if cfg.get("fallback_matrix_approve"):
                log(f"{p.id}: relay register failed ({exc}); "
                    f"falling back to legacy Matrix approval")
                return self.run_flow_matrix(p, emit, result, cmd)
            return result({"ok": False, "status": "channel_down",
                           "detail": f"approval relay unreachable: {exc}"})

        try:
            me = self.wh.me()
            plain, body_html = self.announce_url(p, url, ttl)
            sent = self.wh.send(plain, body_html)
            room_id = sent.get("room") or me.get("room")
            watch_ids = {sent.get("event_id")} - {None, ""}
            since_ts_ms = int(time.time() * 1000)
        except Exception as exc:
            ch.revoke(p.id)
            return result({"ok": False, "status": "error",
                           "detail": f"cannot announce in Matrix via "
                                     f"{cfg['webhooker_url']}: {exc}"})
        log(f"{p.id}: announced (URL approval) in {room_id}")
        emit({"event": "pending", "request_id": p.id, "command": cmd,
              "url": url})

        def hint() -> None:
            self.wh.send_notice(
                f"🔐 {p.id}: approval only works via the link above "
                f"(including your password) — 👍 no longer approves.")

        def remind_url(pend: PendingRequest) -> str | None:
            try:
                resp = self.wh.send(
                    f"🚨 {pend.id}: approval pending — "
                    f"{url}\nIt expires soon. 👎 = reject.")
                log(f"{pend.id}: URL reminder sent")
                return resp.get("event_id")
            except Exception as exc:
                log(f"{pend.id}: URL reminder failed: {exc}")
                return None

        deadline = time.monotonic() + ttl + 10  # slack past the relay TTL
        remind_after = float(cfg.get("approve_remind_s") or 0)
        remind_at = (time.monotonic() + remind_after
                     if remind_after > 0 else None)
        try:
            return self._wait_url_decision(p, ch, key, gkey, room_id,
                                           since_ts_ms, deadline, remind_at,
                                           emit, watch_ids, hint, remind_url,
                                           result, cmd)
        finally:
            ch.done(p.id)

    def _wait_url_decision(self, p, ch, key, gkey, room_id, since_ts_ms,
                           deadline, remind_at, emit, watch_ids, hint,
                           remind_url, result, cmd) -> dict:
        cfg = self.cfg

        def finish(status: str, extra: dict | None = None,
                   history: dict | None = None) -> dict:
            if history:
                self.append_history(history)
            out = {"ok": False, "status": status}
            out.update(extra or {})
            return result(out)

        while time.monotonic() < deadline:
            if p.cancel.is_set():
                ch.revoke(p.id)
                log(f"{p.id}: cancelled")
                return finish("cancelled",
                              {"detail": "request cancelled (client "
                                         "disconnected or 'cancel')"},
                              {"ts": utc_stamp(), "id": p.id, "command": cmd,
                               "reason": p.reason, "status": "cancelled"})
            ev = ch.wait(p.id, timeout=0.5)
            if ev is not None:
                op = ev.get("op")
                if op == "channel_down":
                    return finish("channel_down",
                                  {"detail": "approval relay connection "
                                             f"lost: {ev.get('detail')}"})
                if op == "expired":
                    self.wh.send_notice(f"⌛ sudo {p.id} expired unused")
                    return finish("expired",
                                  {"detail": f"link unused; nobody approved "
                                             f"within {cfg['approve_ttl_s']}s"},
                                  {"ts": utc_stamp(), "id": p.id,
                                   "command": cmd, "reason": p.reason,
                                   "status": "expired", "source": "url"})
                if op == "decision":
                    if ev.get("decision") == "deny":
                        self.wh.send_notice(f"🚫 sudo {p.id} denied on "
                                            f"the approval page")
                        return finish("denied", {"approver": "approval page"},
                                      {"ts": utc_stamp(), "id": p.id,
                                       "command": cmd, "reason": p.reason,
                                       "status": "denied", "source": "url"})
                    verdict = self._consume_approval(p, key, ev, ch)
                    if verdict is None:
                        continue  # bad blob or wrong password — page retries
                    if isinstance(verdict, tuple):
                        # ("denied", reason): crypto/identity failure
                        return finish("denied",
                                      {"detail": verdict[1],
                                       "approver": "approval page"})
                    password, secrets_d, scope = verdict
                    if scope.startswith("same:"):
                        try:
                            minutes = min(max(1, int(scope.split(":", 1)[1])),
                                          60)
                        except ValueError:
                            minutes = 1
                        self.store_grant(gkey, password, secrets_d, minutes,
                                         cmd)
                    ch.report(p.id, "done")
                    return self.execute(
                        p, result, secrets_d,
                        approver=f"{cfg['approve_user']} via approve link "
                                 f"(password verified)",
                        password=password, scope=scope, source="url")
            # deny-only Matrix watch, in short slices
            try:
                decision, actor = self.wait_matrix(
                    p, room_id, since_ts_ms,
                    min(deadline, time.monotonic() + 1.0), remind_at, emit,
                    watch_ids, deny_only=True, approve_hint=hint,
                    remind=remind_url)
            except ClientGone:
                p.cancel.set()
                continue
            if decision == "deny":
                ch.revoke(p.id)
                self.wh.send_notice(f"🚫 sudo {p.id} denied via Matrix "
                                    f"by {actor}")
                return finish("denied", {"approver": actor},
                              {"ts": utc_stamp(), "id": p.id, "command": cmd,
                               "reason": p.reason, "status": "denied",
                               "source": "matrix-deny"})
        return finish("expired",
                      {"detail": f"no approval within "
                                 f"{cfg['approve_ttl_s']}s"},
                      {"ts": utc_stamp(), "id": p.id, "command": cmd,
                       "reason": p.reason, "status": "expired",
                       "source": "url"})

    def _consume_approval(self, p, key, ev, ch):
        """Decrypt + check one approval payload.

        Returns (password, secrets, scope) on success, None to let the page
        retry, or ("denied", reason) for unrecoverable problems.
        """
        cfg = self.cfg
        import approve_client
        payload = ev.get("payload") or {}
        try:
            blob = approve_client.open_payload(
                key, payload.get("ek", ""), payload.get("iv", ""),
                payload.get("ct", ""))
        except Exception as exc:
            log(f"{p.id}: cannot decrypt approval payload: {exc}")
            ch.report(p.id, "error")
            return ("denied", f"unreadable approval payload: {exc}")
        finally:
            payload = None
        if blob.get("id") != p.id:
            log(f"{p.id}: approval payload bound to wrong request id — "
                f"rejected")
            ch.report(p.id, "error")
            return ("denied", "approval payload was not meant for this "
                              "request")
        if abs(time.time() - float(blob.get("ts") or 0)) > 900:
            ch.report(p.id, "error")
            return ("denied", "approval payload is stale")
        password = str(blob.get("password") or "")
        secrets_d = {k: str(v) for k, v in (blob.get("secrets") or {}).items()
                     if k in p.secret_names and SECRET_NAME_RE.fullmatch(k)}
        if not verify_login_password(cfg["approve_user"], password):
            log(f"{p.id}: password check failed")
            self.wh.send_notice(f"🔐 sudo {p.id}: wrong password rejected")
            ch.report(p.id, "auth_failed")
            return None
        scope = str(blob.get("scope") or "once")
        if not scope.startswith(("once", "same:")):
            scope = "once"
        return password, secrets_d, scope

    # -- legacy Matrix approval (fallback; approval only via 👍 from Matrix) --

    def run_flow_matrix(self, p: PendingRequest, emit, result, cmd: str) -> dict:
        cfg = self.cfg
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

        return self.execute(p, result, {},
                            approver=f"{actor} via Matrix 👍",
                            source="matrix")

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
        relay = {"url": (self.cfg.get("approve_url") or "").strip() or None}
        if self.channel is not None:
            relay["connected"] = self.channel.connected
        elif (self.cfg.get("approve_url") or "").strip():
            relay["connected"] = False
            relay["error"] = self.channel_error or "not initialised"
        return {"running_as_uid": os.getuid(),
                "socket": self.cfg["socket_path"],
                "pending": pend,
                "approval_relay": relay,
                "grants": self.grant_list(),
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
        if self.channel is not None:
            self.channel.revoke(rid)
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
        elif op == "grants":
            self.reply({"result": {"ok": True,
                                   "grants": app.grant_list()}})
        elif op == "revoke_grants":
            self.reply({"result": app.grant_revoke(str(msg.get("id") or ""))})
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
        secret_names = normalize_secret_names(msg.get("secret_vars"), argv)
        if sum(len(a) for a in argv) > 8000:
            self.reply({"result": {"ok": False, "status": "error",
                                   "detail": "command too long for the "
                                             "approval page (>8000 chars)"}})
            return
        p = PendingRequest(request_id, argv, str(msg.get("reason") or ""),
                           msg.get("timeout_s"), secret_names)
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


def tool_sudo_run(command, reason: str = "", timeout_s=None,
                  secret_vars=None) -> dict:
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
                           f"{e.get('request_id')} — open the approval "
                           f"link (see Matrix)")
        elif e.get("event") == "reminding":
            desktop_notify(True, "InteractiveSudo — still waiting",
                           f"{e.get('request_id')}: approve via the link "
                           f"or 👎 in Matrix")

    return daemon_call(cfg, {"op": "run", "command": argv,
                             "reason": reason or "", "timeout_s": timeout_s,
                             "secret_vars": secret_vars or []},
                       on_event)


def tool_sudo_status() -> dict:
    return daemon_call(load_user_config(), {"op": "status"})


def tool_sudo_grants(action: str = "list", grant_id: str = "") -> dict:
    op = "grants" if action == "list" else "revoke_grants"
    return daemon_call(load_user_config(), {"op": op, "id": grant_id})


# ---------------------------------------------------------------------------
# MCP server (user-side)
# ---------------------------------------------------------------------------


def serve() -> None:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(
        "interactive-sudo",
        instructions=(
            "Human-in-the-loop root. Use sudo_run for ANY command that needs "
            "root. The user receives a one-time HTTPS approval link in "
            "Matrix: they read the command there and approve with their "
            "password (end-to-end encrypted). 👎/no on the Matrix message "
            "denies; 👍 no longer approves. Never put secrets in command or "
            "reason — if a command needs one, list the variable name in "
            "secret_vars; the user types the value on the approval page and "
            "it is injected as an env var at exec time only (never visible "
            "to you). Put a short human-readable reason in every call."
        ),
    )

    @mcp.tool()
    def sudo_run(command: str | list[str], reason: str = "",
                 timeout_s: int | None = None,
                 secret_vars: list[str] | None = None) -> dict:
        """Run a command as root after interactive human approval.

        The user gets a single-use approval link (plus a Matrix notice):
        they review command + reason there and approve with their password.
        👎/no on the Matrix message denies. Requests expire unused.
        Returns ok, exit_code, stdout, stderr (secrets scrubbed from output).

        Args:
            command: argv list (preferred) or shell string.
            reason: short human explanation shown on the approval page.
            timeout_s: max runtime of the command (default from config).
            secret_vars: names the command needs as $VARS; the user enters
                their values encrypted on the approval page. $NAME in a
                shell command is detected automatically.
        """
        return tool_sudo_run(command, reason=reason, timeout_s=timeout_s,
                             secret_vars=secret_vars)

    @mcp.tool()
    def sudo_status() -> dict:
        """Daemon health, relay connection, grants, pending, recent history."""
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
    relay = st.get("approval_relay") or {}
    if relay.get("url"):
        if relay.get("connected"):
            print(f"relay   : connected  {relay['url']}")
        else:
            print(f"relay   : DOWN ({relay.get('error')})  {relay['url']}")
    grants = st.get("grants") or []
    for g in grants:
        print(f"grant   : {g['id']}  {g['expires_in_s']}s left  "
              f"{g['command'][:60]}")
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


def cmd_revoke(args) -> int:
    what = (args.what or "list").strip()
    if what == "list":
        res = tool_sudo_grants("list")
        grants = res.get("grants") or []
        if not grants:
            print("grants: none")
        for g in grants:
            print(f"{g['id']}  {g['expires_in_s']:>5}s  {g['command'][:80]}")
        return 0
    res = tool_sudo_grants("revoke", "" if what == "all" else what)
    if res.get("ok"):
        print(f"revoked {res.get('revoked')} grant(s)")
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
    p_rev = sub.add_parser("revoke",
                           help="list/revoke 'same command' grants")
    p_rev.add_argument("what", nargs="?", default="list")
    args = parser.parse_args()
    args.cmd = args.cmd or "serve"
    handlers = {
        "serve": lambda _a: serve(),
        "daemon": lambda _a: serve_daemon(),
        "status": cmd_status,
        "history": cmd_history,
        "cancel": cmd_cancel,
        "revoke": cmd_revoke,
    }
    handlers[args.cmd](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
