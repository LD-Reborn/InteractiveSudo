# InteractiveSudoMCP

Human-in-the-loop **root** for coding agents (e.g. OpenCode). The agent can
never run a privileged command unattended: every `sudo_run` call produces a
**single-use HTTPS approval link** and only clicking it **plus typing your
password** makes the root daemon execute the command. The password travels
end-to-end-encrypted; it appears nowhere else — not in chat, not in the
agent's context, not in any log.

## Architecture (v3)

| Part | Runs as | What it does |
|---|---|---|
| **Root daemon** (`mcp_server.py daemon`, systemd) | root | Denylist → registers request with the relay over WSS (PSK) → posts a one-time link in Matrix → waits → decrypts the approval, verifies your password (`pam_check`, PAM) → executes as root → history. |
| **Approval relay** (`approve_server.py`, your public host) | non-root user, behind nginx/TLS | Blind relay: serves the approval page, forwards E2EE ciphertext to the daemon's open WSS. Cannot read passwords/secrets, keeps no state on disk. Stdlib-only. |
| **MCP server** (`mcp_server.py serve`, started by the agent) | you | Thin forwarder over a Unix socket + desktop notifications. No secrets. |

```
agent ──sudo_run(cmd, reason, secret_vars)──▶ MCP forwarder ──unix sock──▶ root daemon
                                                                        │ 1. denylist (instant refusal)
                                                                        │ 2. WSS register (PSK) + ephemeral RSA key
                                                                        │    ◀── one-time token
                                                                        │ 3. Matrix: "approval pending" + link
                                                                        │    https://approve.host/#/r/<token>
                                                                        │    (token = URL fragment → never in any log)
   you ── open link ──▶ relay page ── GET meta (Bearer token) ────────────┤
       reads command/reason/secrets, types password ──▶ RSA-OAEP+AES-GCM │ 4. relay forwards ciphertext
                                                                        │    over the already-open WSS
                                                                        │ 5. decrypt, PAM verify (pam_check)
                                                                        │ 6. run as root (argv, cwd=/, min env,
                                                                        │    secrets injected, output scrubbed)
                                                                        ▼
                                                              {ok, exit_code, stdout, stderr}
```

Approval is **two-factor**: possession of the single-use URL (registered
only while pending, 256-bit token, TTL, single-use, rate limits) **and**
knowledge of your login password. The Matrix channel is **deny-only**: 👎/no
on the message aborts the request; 👍/yes never approves (that was the
single-factor weakness this replaces).

## Features

- **Named secrets as variables** — `sudo_run(secret_vars=["GIT_TOKEN"])`
  (or `$GIT_TOKEN` inside the command, auto-detected) shows a field on the
  approval page; the value is encrypted in the browser (WebCrypto),
  injected into the command's environment at exec time only, scrubbed from
  stdout/stderr, and never visible to the agent or the relay.
- **Scope dropdown** — "Nur dieses eine Mal" (default) or "Diesen Befehl
  nochmal für N Minuten" (grant stays in root RAM, listed by `sudo_status`,
  revocable with `revoke`). There is deliberately **no** "allow all".
- **Denylist** substrings are refused before anyone is even asked.
- **Legacy pure-Matrix mode** still works when `approve_url` is empty;
  `fallback_matrix_approve: true` uses it when the relay is unreachable.
- **Client-initiated everything**: the PC needs no inbound port or cert —
  it dials out to your existing nginx/TLS host.

## Tools (MCP, stdio)

| Tool | What it does |
|---|---|
| `sudo_run(command, reason, timeout_s?, secret_vars?)` | Ask for approval, then run as root. Returns `ok`, `exit_code`, `stdout`, `stderr` (secrets scrubbed). |
| `sudo_status()` | Daemon health, relay connection, active grants, pending, history. |

CLI (user side; approval is never possible from the CLI by design):

```sh
python3 mcp_server.py status          # daemon + relay + grants + recent
python3 mcp_server.py history -n 10   # recent completed requests
python3 mcp_server.py cancel last     # cancel a pending request
python3 mcp_server.py revoke list     # active "same command" grants
python3 mcp_server.py revoke all      # revoke them
```

## Install

**1) The relay** (once, on your public Linux host; needs root there):
deploy `approve_server.py` behind nginx with a TLS cert, e.g.

```ini
# /etc/approved/config.json  (0640, psk = shared with the daemon)
{"bind": "127.0.0.1", "port": 8095, "psk": "<32+ byte secret>",
 "ttl_s": 300, "same_cmd_minutes": 10, "max_attempts": 3,
 "page_title": "approve.example.com"}
```

nginx: `location / { proxy_pass http://127.0.0.1:8095; proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";
proxy_read_timeout 3600; }` — see the relay docs in `approve_server.py` for a complete
example installer (systemd unit, DNS record, certbot, vhost).

**2) The daemon** (this machine — deliberate HUMAN sudo action):

```sh
cd ~/.config/InteractiveSudo
echo -n '<the same PSK>' > secrets/approve_psk   # chmod 600; removed from /etc
./install.sh
```

`install.sh` deploys the daemon code root-owned to
`/usr/local/lib/interactivesudo/`, creates `/etc/interactivesudo/`
(config.json 0640, api_key + approve_psk 0600 — kept on re-runs) and
(installs and restarts) the systemd unit.

**3) Enable URL approval** in `/etc/interactivesudo/config.json`:

```json
"approve_url": "wss://approve.example.com/ws/v1/client",
"approve_psk_file": "/etc/interactivesudo/approve_psk",
"approve_user": "yourlogin"
```

**Important:** never keep `secrets/*` inside a synced/backed-up folder.
`install.sh` imports them to `/etc` and tells you to delete the copies;
rotate anything that ever landed in a chat.

## Configuration (daemon, `/etc/interactivesudo/config.json`)

| Key | Default | Meaning |
|---|---|---|
| `webhooker_url` | `http://localhost:8080` | MatrixWebhooker base URL |
| `api_key_file` | `/etc/interactivesudo/api_key` | bot API key (root-only) |
| `approve_url` | *(empty = legacy mode)* | relay WSS endpoint |
| `approve_psk_file` | `/etc/interactivesudo/approve_psk` | registration key (root-only) |
| `approve_user` | `operator` | account whose password approves |
| `approve_ttl_s` | `300` | link lifetime / wait deadline |
| `approve_remind_s` | `180` | Matrix mention ping (`0` = off) |
| `fallback_matrix_approve` | `false` | legacy 👍 if relay down |
| `socket_path` / `socket_group` | `/run/interactivesudo/agent.sock` | daemon socket |
| `state_dir` | `/var/lib/interactivesudo` | history (root-only) |
| `wait_timeout_s` / `remind_after_s` | `600` / `300` | legacy-mode timing |
| `command_timeout_s` | `300` | max runtime of the command |
| `max_pending` | `5` | refuse new requests beyond this |
| `denylist` | see file | substrings refused without asking |

Client (`config.json` next to `mcp_server.py`): `socket_path`,
`desktop_notify`. Env overrides: `SUDOMCP_CONFIG`, `SUDOMCP_DAEMON_CONFIG`.

## Security model

- Approval = one-time URL (possession) **and** your password (knowledge),
  verified against PAM (service `sudo`) via the small `pam_check` C helper
  inside the root daemon.
- Password + named secrets: per-request ephemeral RSA-2048 keypair, browser
  encrypts (WebCrypto RSA-OAEP + AES-256-GCM); the relay only ever handles
  opaque ciphertext; nothing touches disk or logs; output is scrubbed.
- Result channel (v3.1): the page generates a second ephemeral RSA keypair;
  after execution the daemon seals exit code + output tails back to it, so
  the page can show the outcome in a collapsible panel — the relay stores
  ciphertext only. The private key lives in that browser's localStorage
  (per link token), so the same browser can re-open an old link and still
  decrypt; other browsers see "result exists" but cannot read it. Disable
  with `"report_results": false` in the daemon config.
- The token lives in the URL **fragment** — browsers never send fragments,
  so nginx access logs, `Referer` and Matrix link-preview crawlers cannot
  see it. The page strips it from the address bar after loading.
- GET only displays (safe for unfurlers); POST decides; single-use tokens;
  attempts/rate limits; generic 404s; only truncated token hashes in logs.
- Registration with the relay requires the PSK (root-only file) — nobody
  else can inject approval pages.
- No local approval channel: the bot's own messages are ignored; a
  compromised user account cannot approve or (without the password)
  escalate. Denylist still applies to every path, including grants.
- Commands run as root with a minimal environment, `cwd=/`, timeout;
  client disconnect or 👎 cancels before execution.
- Trust anchors: your password, the PSK, the relay host's TLS, and your
  Matrix account (for the deny path). A compromised relay can at most
  refuse/serve stale pages — it cannot forge an approval (no PSK-authorized
  channel ⇒ nowhere to deliver a payload) and cannot read any secret.

## Notes

- The daemon needs `python3-cryptography` (apt) and `approve_client.py`
  beside it; the relay is stdlib-only (Python ≥ 3.10).
- The password must be the daemon user's actual login password; password
  policies/lockouts (`pam_faillock`) apply to failed attempts.
- Registered in `~/.config/opencode/opencode.json` under `mcp.servers.sudo`.
- Tests: `python3 test_e2e_local.py` (relay + channel + E2EE + page-API
  parity through Node's WebCrypto) — no network, uses 127.0.0.1 only.
