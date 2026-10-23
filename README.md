# InteractiveSudoMCP

Human-in-the-loop **root** for coding agents (e.g. OpenCode). The agent can
never run a privileged command unattended: every `sudo_run` call is announced
to you in Matrix, and only a **👍 from you** makes a root daemon execute it.
No passwords anywhere, and no local approval channel — not even the agent
itself can approve.

## Architecture

One file (`mcp_server.py`), two roles:

| Role | Runs as | What it does |
|---|---|---|
| **Root daemon** (`daemon` subcommand, systemd) | `root` | Denylist check → Matrix announcement → waits for your 👍/👎 → executes as root → history. Stdlib-only. |
| **MCP server** (`serve` subcommand, started by the agent) | you | Thin forwarder: sends requests to the daemon over a Unix socket, fires desktop notifications. No secrets, no privileges. |

```
agent ── sudo_run(cmd, reason) ──▶ MCP server (you) ── Unix socket ──▶ root daemon
                                                                        │ 1. denylist (instant refusal)
                                                                        │ 2. POST /webhook ──▶ your Matrix room
                                                                        │    (client fires notify-send)
                                                                        │ 3. wait for 👍/👎 — Matrix ONLY
                                                                        │    └ remind_after_s: 🚨 mention ping
                                                                        │ 4. client disconnected? → cancelled
                                                                        ▼
                                                                  approved?
                                                                  ├─ no/expired → {ok:false, status:...}
                                                                  └─ 👍 yes → run as root (argv, cwd=/, min env)
                                                                            → {ok, exit_code, stdout, stderr}
```

## Why a root daemon instead of sudo + password?

Passwords in chat are the problem this replaced: a `yes <password>` reply
lands in the Matrix homeserver's history, on every synced device, and can
leak into the agent's context. The daemon removes passwords entirely — and
because the agent (running as you) has a shell, **local approval channels
would be forgeable by a compromised account**. So approval comes only from
Matrix, out-of-band from this machine.

Verified properties (live-tested):
- 👍 reaction on the request/reminder message, or `yes`/`ja` text, approves;
  👎/`no` denies; anything else is ignored.
- The **bot's own 👍 is ignored** — a local process cannot self-approve.
- Closing the connection (agent gave up) **cancels** the request.
- `cancel last` from a terminal cancels a pending request.

## Tools (MCP, stdio)

| Tool | What it does |
|---|---|
| `sudo_run(command, reason, timeout_s?)` | Announces in Matrix, waits for 👍/👎, runs as root on approval, returns `ok`, `exit_code`, `stdout`, `stderr`. |
| `sudo_status()` | Daemon health, bot/room, pending requests, recent history. |

`command` is preferably an argv list (`["apt", "install", "foo"]`); a shell
string is also accepted (runs through `sh -c` — you approve exactly that string).

## Approving

React **👍** on the request message (or the 🚨 reminder) to approve,
**👎** to deny — or reply in the room: `yes`/`ja`/`ok` … approve,
`no`/`nein`/`abort` … deny. Nothing else counts. If nobody decides within
`wait_timeout_s` (default 600s) the request expires; at `remind_after_s`
(default 300s) the bot sends a **mention** (pushes your phone) and the
desktop notification re-fires.

CLI (user side, no approval possible by design):

```sh
python3 mcp_server.py status          # daemon health + pending + history
python3 mcp_server.py history -n 10   # recent completed requests
python3 mcp_server.py cancel last     # cancel a pending request
```

## Install (human sudo action — do not let the agent run this)

```sh
cd ~/.config/InteractiveSudo
./install.sh
```

`install.sh` deploys:

- `/usr/local/lib/interactivesudo/mcp_server.py` — daemon code, **root-owned**
  (a user-writable daemon would be an escalation path: edit code, wait for
  restart → root runs your code). Edit in `~/.config/InteractiveSudo/` and
  re-run `install.sh` to deploy.
- `/etc/interactivesudo/config.json` (0640 root) and
  `/etc/interactivesudo/api_key` (0600 root) — created once, then preserved.
- `/etc/systemd/system/interactivesudo.service` — enabled, started.

Check: `systemctl status interactivesudo`, `journalctl -u interactivesudo -f`,
then `python3 mcp_server.py status`.

**Important:** never keep `secrets/api_key` inside a synced or backed-up
folder (cloud sync pushes it to servers and all your devices). `install.sh`
imports it to `/etc` and tells you to delete the project copy — and you
should **rotate the key** in MatrixWebhooker afterwards.

## Configuration

Daemon (`/etc/interactivesudo/config.json`, see `daemon_config.example.json`):

| Key | Default | Meaning |
|---|---|---|
| `webhooker_url` | `http://localhost:8080` | MatrixWebhooker base URL |
| `api_key_file` | `/etc/interactivesudo/api_key` | bot API key (root-only) |
| `socket_path` | `/run/interactivesudo/agent.sock` | daemon socket (0660, group `socket_group`) |
| `socket_group` | your username | group allowed to submit requests |
| `state_dir` | `/var/lib/interactivesudo` | history (root-only) |
| `wait_timeout_s` | `600` | how long to wait for 👍/👎 |
| `remind_after_s` | `300` | mention ping after this long (`0` = off) |
| `remind_mxid` | your MXID | mentioned so the ping pushes |
| `command_timeout_s` | `300` | max runtime of the command |
| `max_pending` | `5` | refuse new requests beyond this |
| `denylist` | see file | substrings refused without asking |

Client (`config.json` next to `mcp_server.py`): `socket_path`, `desktop_notify`.
Env overrides: `SUDOMCP_CONFIG` (client), `SUDOMCP_DAEMON_CONFIG` (daemon).

## Security model

- **Approval only via Matrix** from your account; the bot's own messages are
  ignored. No decision files, no CLI approve — a compromised user account
  (or the agent) cannot self-approve.
- **Root-owned daemon code + key**; deployment is a deliberate human sudo
  (`install.sh`).
- **Denylist** substrings are refused instantly without asking.
- Commands run as root with a minimal environment, `cwd=/`, and a timeout.
- Client disconnect ⇒ request cancelled before execution.
- History (`/var/lib/interactivesudo/history.jsonl`, 0600) records command,
  reason, approver, exit code.
- Trust anchor: your Matrix account + homeserver. If the homeserver is
  compromised, an attacker can send 👍 — keep E2EE/offline-key hygiene.

## Notes

- The MCP server (user-side) needs the venv (`mcp` package); the daemon is
  stdlib-only and runs on the system python.
- A command that reads stdin gets EOF (captured output, no tty).
- Registered in `~/.config/opencode/opencode.json` under `mcp.servers.sudo`.
