#!/usr/bin/env python3
"""InteractiveSudoMCP — human-in-the-loop `sudo` for coding agents.

MCP tools (stdio transport):
  sudo_run(command, reason, timeout_s)  Ask the human to approve, then run via sudo.
  sudo_status()                         Webhooker health, pending requests, recent history.

CLI (same file, no MCP required):
  mcp_server.py serve                     Run the MCP server (default command).
  mcp_server.py approve [id|last] [pw]    Approve a pending request from a terminal.
  mcp_server.py deny    [id|last]         Deny a pending request.
  mcp_server.py status                    Pending requests + webhooker health.
  mcp_server.py history [-n N]            Show recent completed requests.

How it works
------------
1. The agent calls sudo_run with the command (argv list or shell string) and a reason.
2. The server announces the request in the Matrix room (via MatrixWebhooker),
   fires a desktop notification, and waits.
3. The human replies "yes" / "no" (and "yes <password>" if a password is
   needed) in Matrix — or approves/denies from any terminal with the CLI.
4. Only on approval does the server run `sudo -n` (or `sudo -S` with the
   provided password) and return stdout/stderr/exit code to the agent.

Security model
--------------
- Every run requires an explicit human decision; nothing is auto-approved.
- A `denylist` of substrings is refused immediately without asking.
- Passwords are never written to disk (the decision file is deleted after
  use and holds at most the just-provided password). History logs only
  booleans like "password_provided".
- A password that was actually used may be kept in server memory for
  `password_ttl_s` seconds (0 = never cache).
"""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = PROJECT_DIR / "config.json"

DEFAULTS: dict = {
    "webhooker_url": "http://localhost:8083",
    "bot_name": "mybot",
    "api_key_file": "secrets/api_key",
    "state_dir": "",  # default: ~/.local/state/interactivesudo
    "desktop_notify": True,
    "poll_interval_s": 1.5,
    "wait_timeout_s": 600,          # how long to wait for yes/no
    "password_ask_timeout_s": 180,  # how long to wait for a password
    "command_timeout_s": 300,       # max runtime of the sudo command itself
    "password_ttl_s": 300,          # in-memory cache of a working password
    "max_output_chars": 20000,      # stdout/stderr capture cap
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

APPROVE_WORDS = {
    "yes", "y", "yep", "yeah", "ok", "okay", "approve", "approved", "go", "sure",
    "ja", "bitte", "klar",
}
DENY_WORDS = {
    "no", "n", "nope", "deny", "denied", "abort", "cancel", "stop",
    "nein", "abbrechen", "ablehnen", "ablehne",
}

# ---------------------------------------------------------------------------
# config / state
# ---------------------------------------------------------------------------


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    cfg_path = Path(os.environ.get("SUDOMCP_CONFIG", "") or DEFAULT_CONFIG_PATH)
    if cfg_path.exists():
        try:
            user_cfg = json.loads(cfg_path.read_text())
        except Exception as exc:
            raise SystemExit(f"config error in {cfg_path}: {exc}") from exc
        if not isinstance(user_cfg, dict):
            raise SystemExit(f"config error in {cfg_path}: top level must be an object")
        cfg.update(user_cfg)
    for key in ("api_key_file", "state_dir"):
        if cfg.get(key) and not Path(str(cfg[key])).is_absolute():
            cfg[key] = str((PROJECT_DIR / str(cfg[key])).resolve())
    if not cfg.get("state_dir"):
        cfg["state_dir"] = str(Path.home() / ".local" / "state" / "interactivesudo")
    Path(cfg["state_dir"]).mkdir(parents=True, exist_ok=True)
    return cfg


def read_api_key(cfg: dict) -> str:
    key_path = Path(cfg["api_key_file"])
    if not key_path.exists():
        raise RuntimeError(
            f"api key file not found: {key_path} — copy your MatrixWebhooker "
            f"bot api_key there (chmod 600)"
        )
    key = key_path.read_text().strip()
    if not key:
        raise RuntimeError(f"api key file is empty: {key_path}")
    return key


def state_paths(cfg: dict) -> tuple[Path, Path]:
    root = Path(cfg["state_dir"])
    return root, root / "requests"


def write_json(path: Path, obj, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")
    os.chmod(path, mode)


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def append_history(cfg: dict, entry: dict) -> None:
    root, _ = state_paths(cfg)
    with open(root / "history.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    os.chmod(root / "history.jsonl", 0o600)


def tail_history(cfg: dict, n: int = 5):
    root, _ = state_paths(cfg)
    p = root / "history.jsonl"
    if not p.exists():
        return []
    lines = p.read_text().splitlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return list(reversed(out))


def pending_requests(cfg: dict) -> list[dict]:
    _, req_root = state_paths(cfg)
    if not req_root.exists():
        return []
    out = []
    for p in sorted(req_root.glob("*.json")):
        rec = read_json(p)
        if rec and rec.get("status") == "waiting":
            out.append(rec)
    return list(reversed(out))


def resolve_request_id(cfg: dict, arg: str) -> str:
    if arg and arg != "last":
        return arg
    root, _ = state_paths(cfg)
    last = root / "last_request"
    if last.exists():
        return last.read_text().strip()
    pend = pending_requests(cfg)
    if pend:
        return pend[0]["id"]
    raise SystemExit("no pending request found (nothing to approve/deny)")


def set_decision(cfg: dict, request_id: str, decision: str, password: str | None,
                 actor: str) -> None:
    _, req_root = state_paths(cfg)
    write_json(
        req_root / f"{request_id}" / "decision.json",
        {
            "decision": decision,
            "password": password,
            "source": "cli",
            "actor": actor,
            "ts": utc_stamp(),
        },
    )


# ---------------------------------------------------------------------------
# webhooker (Matrix) client
# ---------------------------------------------------------------------------


class Webhooker:
    """Tiny client for MatrixWebhooker (localhost:8083)."""

    def __init__(self, cfg: dict):
        self.base = cfg["webhooker_url"].rstrip("/")
        self.key = read_api_key(cfg)
        self.bot_name = cfg["bot_name"]
        self.bot_user: str | None = None
        self.client = httpx.Client(timeout=10.0)
        self._headers = {"X-API-Key": self.key}

    def health(self) -> dict:
        r = self.client.get(self.base + "/health")
        r.raise_for_status()
        return r.json()

    def me(self) -> dict:
        r = self.client.get(self.base + "/me", headers=self._headers)
        r.raise_for_status()
        d = r.json()
        self.bot_user = d.get("user")
        return d

    def send(self, text: str, html_body: str | None = None,
             msgtype: str = "m.text") -> dict:
        body: dict = {"text": text, "msgtype": msgtype}
        if html_body:
            body["html"] = html_body
        r = self.client.post(self.base + "/webhook", headers=self._headers, json=body)
        r.raise_for_status()
        return r.json()

    def send_notice(self, text: str) -> None:
        try:
            self.send(text, msgtype="m.notice")
        except Exception:
            pass

    def messages(self, room_id: str, limit: int = 25) -> list[dict]:
        r = self.client.get(
            f"{self.base}/rooms/{room_id}/messages",
            headers=self._headers,
            params={"limit": limit},
        )
        r.raise_for_status()
        return r.json().get("messages", [])


# ---------------------------------------------------------------------------
# core flow
# ---------------------------------------------------------------------------

_PW_CACHE: dict = {"pw": None, "expires": 0.0}


def cached_password(cfg: dict) -> str | None:
    if _PW_CACHE["pw"] is None:
        return None
    if time.monotonic() > _PW_CACHE["expires"]:
        _PW_CACHE.update(pw=None, expires=0.0)
        return None
    return _PW_CACHE["pw"]


def remember_password(cfg: dict, pw: str) -> None:
    ttl = int(cfg.get("password_ttl_s") or 0)
    if ttl > 0:
        _PW_CACHE.update(pw=pw, expires=time.monotonic() + ttl)


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


def parse_reply(raw: str) -> tuple[str | None, str | None]:
    """Parse a human reply into (decision, password).

    decision is "approve" | "deny" | None (not a decision).
    """
    text = (raw or "").strip().strip("`").strip()
    if not text:
        return None, None
    words = [w.lower().rstrip("!.") for w in text.split()]
    first = words[0]
    if first in APPROVE_WORDS:
        rest = text.split(None, 1)[1].strip() if len(text.split()) > 1 else None
        return "approve", rest or None
    if first in DENY_WORDS:
        return "deny", None
    # Fallback: a decision keyword anywhere in the message.
    if any(w in APPROVE_WORDS for w in words):
        return "approve", None
    if any(w in DENY_WORDS for w in words):
        return "deny", None
    return None, None


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


def wait_for_decision(cfg: dict, wh: Webhooker | None, room_id: str | None,
                      since_ts_ms: int, deadline_monotonic: float,
                      request_id: str) -> dict | None:
    """Poll for a decision: local decision file (CLI) or Matrix reply.

    Returns {"decision","password","source","actor"} or None on timeout.
    """
    _, req_root = state_paths(cfg)
    decision_file = req_root / request_id / "decision.json"
    interval = float(cfg["poll_interval_s"])
    while True:
        if decision_file.exists():
            d = read_json(decision_file)
            decision_file.unlink(missing_ok=True)
            if d:
                return d
        if wh is not None and room_id:
            try:
                for m in wh.messages(room_id, limit=25):
                    if m.get("sender") == wh.bot_user:
                        continue
                    ts = m.get("ts") or 0
                    if ts < since_ts_ms - 3000:
                        continue
                    decision, password = parse_reply(m.get("body", ""))
                    if decision is None:
                        continue  # not a decision; keep waiting
                    return {
                        "decision": decision,
                        "password": password,
                        "source": "matrix",
                        "actor": m.get("sender"),
                    }
            except Exception:
                pass  # webhooker hiccup; retry on the next tick
        if time.monotonic() >= deadline_monotonic:
            return None
        time.sleep(interval)


def run_sudo(argv: list[str], password: str | None, timeout_s: int) -> subprocess.CompletedProcess:
    sudo = shutil.which("sudo")
    if not sudo:
        raise RuntimeError("'sudo' not found on PATH")
    if password is not None:
        cmd = [sudo, "-S", "-p", ""] + argv
        stdin_data = password + "\n"
    else:
        cmd = [sudo, "-n", "-p", ""] + argv  # -n: fail instead of prompting
        stdin_data = None
    try:
        return subprocess.run(
            cmd, input=stdin_data, capture_output=True, text=True, timeout=timeout_s
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"command timed out after {timeout_s}s")


def cap(text: str | None, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [truncated {len(text) - limit} more chars]"


def update_request(cfg: dict, request_id: str, **fields) -> None:
    _, req_root = state_paths(cfg)
    p = req_root / f"{request_id}.json"
    rec = read_json(p) or {}
    rec.update(fields)
    rec["ts_updated"] = utc_stamp()
    write_json(p, rec)


def build_messages(rec: dict, request_id: str) -> tuple[str, str]:
    cmd = cmdline_of(rec["command"])
    reason = rec.get("reason") or "-"
    esc = html.escape
    plain = (
        f"🔐 sudo request {request_id}\n"
        f"command: {cmd}\n"
        f"reason: {reason}\n"
        "Reply: yes (approve) · no (deny)\n"
        "If it needs a password: yes <password>\n"
        f"Terminal: {PROJECT_DIR / 'mcp_server.py'} approve {request_id} [password]"
    )
    body = (
        f"🔐 <b>sudo request</b> <code>{esc(request_id)}</code><br>"
        f"command: <code>{esc(cmd)}</code><br>"
        f"<i>reason: {esc(reason)}</i><br>"
        "Reply <b>yes</b> to approve, <b>no</b> to deny.<br>"
        "Needs a password? Reply <b>yes &lt;password&gt;</b>"
    )
    return plain, body


# ---------------------------------------------------------------------------
# tool implementations
# ---------------------------------------------------------------------------


def tool_sudo_run(command, reason: str = "", timeout_s=None) -> dict:
    cfg = load_config()
    t0 = time.monotonic()

    try:
        argv = normalize_command(command)
    except ValueError as exc:
        return {"ok": False, "status": "error", "detail": str(exc)}

    cmd_display = cmdline_of(argv)
    joined = " ".join(argv)
    for pattern in cfg.get("denylist") or []:
        if pattern and pattern in joined:
            return {
                "ok": False,
                "status": "refused_by_policy",
                "detail": f"command matches denylist pattern {pattern!r} — "
                          "denied without asking. Fix the command or adjust "
                          "the denylist in config.json.",
            }

    request_id = "s-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(2).hex()
    rec = {
        "id": request_id,
        "ts": utc_stamp(),
        "command": argv,
        "reason": reason or "",
        "status": "waiting",
        "password_provided": False,
    }
    _, req_root = state_paths(cfg)
    write_json(req_root / f"{request_id}.json", rec)
    (Path(cfg["state_dir"]) / "last_request").write_text(request_id + "\n")

    def result(extra: dict) -> dict:
        base = {
            "ok": False,
            "request_id": request_id,
            "command": cmd_display,
            "duration_s": round(time.monotonic() - t0, 2),
        }
        base.update(extra)
        return base

    # --- announce -------------------------------------------------------
    wh: Webhooker | None = None
    room_id: str | None = None
    since_ts_ms = int(time.time() * 1000)
    matrix_ok = False
    try:
        wh = Webhooker(cfg)
        wh.me()  # validates api key, learns bot user id
        plain, body_html = build_messages(rec, request_id)
        sent = wh.send(plain, body_html)
        room_id = sent.get("room")
        since_ts_ms = int(time.time() * 1000)
        matrix_ok = True
    except Exception as exc:
        matrix_ok = False
        rec["matrix_announce_error"] = str(exc)
    desktop_notify(cfg.get("desktop_notify", True),
                   "InteractiveSudo — approval needed",
                   f"{request_id}: {cmd_display}")

    # --- approval round --------------------------------------------------
    deadline = time.monotonic() + float(cfg["wait_timeout_s"])
    d = wait_for_decision(cfg, wh if matrix_ok else None,
                          room_id if matrix_ok else None,
                          since_ts_ms, deadline, request_id)
    if d is None:
        update_request(cfg, request_id, status="expired",
                       detail="no decision before timeout")
        append_history(cfg, {"ts": utc_stamp(), "id": request_id,
                             "command": cmd_display, "reason": reason,
                             "status": "expired"})
        extra = ("" if matrix_ok
                 else f" (matrix announce failed: {rec.get('matrix_announce_error')})")
        return result({"status": "expired",
                       "detail": f"no decision within {cfg['wait_timeout_s']}s{extra}"})

    if d["decision"] != "approve":
        update_request(cfg, request_id, status="denied", approver=d.get("actor"),
                       source=d.get("source"))
        append_history(cfg, {"ts": utc_stamp(), "id": request_id,
                             "command": cmd_display, "reason": reason,
                             "status": "denied", "approver": d.get("actor"),
                             "source": d.get("source")})
        if wh and matrix_ok:
            wh.send_notice(f"🚫 sudo {request_id} denied by {d.get('actor') or 'user'}")
        return result({"status": "denied", "approver": d.get("actor")})

    # approved
    timeout = int(timeout_s or cfg["command_timeout_s"])
    password = d.get("password") or cached_password(cfg)
    rec["password_provided"] = bool(password)

    proc: subprocess.CompletedProcess | None = None
    if password:
        try:
            proc = run_sudo(argv, password, timeout)
        except RuntimeError as exc:
            proc = None
            detail = str(exc)
        if proc is not None and proc.returncode == 0:
            remember_password(cfg, password)
        else:
            detail = cap((proc.stderr if proc else "") or "failed", 2000)
    else:
        try:
            proc = run_sudo(argv, None, timeout)  # sudo -n
        except RuntimeError as exc:
            return result({"status": "error", "detail": str(exc)})
        if proc.returncode == 0:
            pass
        else:
            # needs a password — second round
            proc = None
            detail = None
            if wh and matrix_ok:
                wh.send(
                    f"🔐 sudo {request_id} was approved but needs a password.\n"
                    f"command: {cmd_display}\n"
                    "Send the password now (or 'no' to abort)."
                )
            desktop_notify(cfg.get("desktop_notify", True),
                           "InteractiveSudo — password needed",
                           f"{request_id}: {cmd_display}")
            deadline = time.monotonic() + float(cfg["password_ask_timeout_s"])
            d2 = wait_for_decision(cfg, wh if matrix_ok else None,
                                   room_id if matrix_ok else None,
                                   int(time.time() * 1000), deadline, request_id)
            if d2 is None or d2["decision"] != "approve" or not d2.get("password"):
                update_request(cfg, request_id, status="denied",
                               detail="no password provided")
                append_history(cfg, {"ts": utc_stamp(), "id": request_id,
                                     "command": cmd_display, "reason": reason,
                                     "status": "denied", "detail": "no password"})
                return result({"status": "denied",
                               "detail": "approved, but no password was provided"})
            password = d2["password"]
            rec["password_provided"] = True
            try:
                proc = run_sudo(argv, password, timeout)
            except RuntimeError as exc:
                return result({"status": "error", "detail": str(exc)})
            if proc.returncode == 0:
                remember_password(cfg, password)

    if proc is None:
        status = "denied" if detail is None else "failed"
        update_request(cfg, request_id, status=status, detail=detail)
        append_history(cfg, {"ts": utc_stamp(), "id": request_id,
                             "command": cmd_display, "reason": reason,
                             "status": status})
        return result({"status": status, "detail": detail})

    ok = proc.returncode == 0
    update_request(cfg, request_id, status="done", ok=ok,
                   exit_code=proc.returncode, approver=d.get("actor"),
                   source=d.get("source"))
    append_history(cfg, {"ts": utc_stamp(), "id": request_id,
                         "command": cmd_display, "reason": reason,
                         "status": "done", "exit_code": proc.returncode,
                         "approver": d.get("actor"), "source": d.get("source"),
                         "password_provided": bool(password)})
    if wh and matrix_ok:
        wh.send_notice(
            f"{'✅' if ok else '❌'} sudo {request_id} finished: exit {proc.returncode}"
        )
    return result({
        "ok": ok,
        "status": "done",
        "approver": d.get("actor"),
        "exit_code": proc.returncode,
        "stdout": cap(proc.stdout, int(cfg["max_output_chars"])),
        "stderr": cap(proc.stderr, int(cfg["max_output_chars"])),
    })


def tool_sudo_status() -> dict:
    cfg = load_config()
    out: dict = {
        "project_dir": str(PROJECT_DIR),
        "state_dir": cfg["state_dir"],
        "bot": cfg["bot_name"],
        "password_cached": cached_password(cfg) is not None,
        "pending": pending_requests(cfg),
        "recent_history": tail_history(cfg, 5),
    }
    try:
        wh = Webhooker(cfg)
        me = wh.me()
        out["webhooker"] = {
            "url": cfg["webhooker_url"],
            "ok": True,
            "bot": me.get("bot"),
            "bot_user": me.get("user"),
            "room": me.get("room"),
        }
    except Exception as exc:
        out["webhooker"] = {"url": cfg["webhooker_url"], "ok": False, "error": str(exc)}
    return out


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------


def serve() -> None:
    import logging
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(
        "interactive-sudo",
        instructions=(
            "Human-in-the-loop sudo. Use sudo_run for ANY command that needs root. "
            "The user is asked in Matrix and must reply 'yes' (and a password if "
            "needed) before anything runs. Put a short human-readable reason in "
            "every call. Never put secrets or passwords in 'reason'."
        ),
    )

    @mcp.tool()
    def sudo_run(command: str | list[str], reason: str = "",
                 timeout_s: int | None = None) -> dict:
        """Run a command via sudo after interactive human approval.

        The request is announced in the user's Matrix room; the user must reply
        'yes' to approve ('no' denies). If sudo needs a password, the user can
        include it: 'yes <password>'. Returns ok, exit_code, stdout, stderr.

        Args:
            command: argv list (preferred) or shell string.
            reason: short human explanation shown to the approver.
            timeout_s: max runtime of the command (default from config).
        """
        return tool_sudo_run(command, reason=reason, timeout_s=timeout_s)

    @mcp.tool()
    def sudo_status() -> dict:
        """Webhooker health, pending requests, cached-password state, recent history."""
        return tool_sudo_status()

    mcp.run(transport="stdio")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_serve(_args) -> int:
    serve()
    return 0


def cmd_approve(args) -> int:
    cfg = load_config()
    rid = resolve_request_id(cfg, args.id)
    password = args.password
    if not password:
        try:
            import getpass
            password = getpass.getpass(f"password for {rid} (blank = none): ") or None
        except (EOFError, KeyboardInterrupt):
            password = None
    set_decision(cfg, rid, "approve", password, os.environ.get("USER", "cli"))
    print(f"approved {rid}" + ("" if password else " (no password)"))
    return 0


def cmd_deny(args) -> int:
    cfg = load_config()
    rid = resolve_request_id(cfg, args.id)
    set_decision(cfg, rid, "deny", None, os.environ.get("USER", "cli"))
    print(f"denied {rid}")
    return 0


def cmd_status(_args) -> int:
    cfg = load_config()
    print(f"project : {PROJECT_DIR}")
    print(f"state   : {cfg['state_dir']}")
    try:
        wh = Webhooker(cfg)
        me = wh.me()
        print(f"webhooker: OK  bot={me.get('bot')} user={me.get('user')} room={me.get('room')}")
    except Exception as exc:
        print(f"webhooker: FAIL ({exc})")
    pend = pending_requests(cfg)
    if pend:
        print("pending requests:")
        for r in pend:
            print(f"  {r['id']}  {cmdline_of(r['command'])}  (since {r.get('ts')})")
    else:
        print("pending requests: none")
    hist = tail_history(cfg, 5)
    if hist:
        print("recent:")
        for h in hist:
            print(f"  {h.get('ts')}  {h.get('id')}  {h.get('status')}  "
                  f"exit={h.get('exit_code')}  {h.get('command', '')[:70]}")
    else:
        print("recent: (none yet)")
    return 0


def cmd_history(args) -> int:
    for h in tail_history(load_config(), args.n):
        print(json.dumps(h, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mcp_server.py",
        description="InteractiveSudoMCP — human-in-the-loop sudo for coding agents.",
    )
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the MCP stdio server (default)")
    p_app = sub.add_parser("approve", help="approve a pending request")
    p_app.add_argument("id", nargs="?", default="last")
    p_app.add_argument("password", nargs="?")
    p_den = sub.add_parser("deny", help="deny a pending request")
    p_den.add_argument("id", nargs="?", default="last")
    sub.add_parser("status", help="show pending requests + health")
    p_hist = sub.add_parser("history", help="show recent requests")
    p_hist.add_argument("-n", type=int, default=10)
    args = parser.parse_args()
    args.cmd = args.cmd or "serve"
    handlers = {
        "serve": cmd_serve,
        "approve": cmd_approve,
        "deny": cmd_deny,
        "status": cmd_status,
        "history": cmd_history,
    }
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
