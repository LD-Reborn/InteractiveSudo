# InteractiveSudoMCP

Human-in-the-loop `sudo` for coding agents (e.g. OpenCode). The agent can never
run a privileged command unattended: every `sudo_run` call announces the exact
command to you in Matrix (plus a desktop notification), and only runs after you
reply **yes** — or after you approve/deny from any terminal via the CLI.

Built for, and tested against, the local **MatrixWebhooker** on
`http://localhost:8080` and bot `mybot`.

## Tools (MCP, stdio)

| Tool | What it does |
|---|---|
| `sudo_run(command, reason, timeout_s?)` | Announces the request in Matrix, waits for your decision, runs `sudo` on approval, returns `ok`, `exit_code`, `stdout`, `stderr`. |
| `sudo_status()` | Webhooker health, bot/room, pending requests, cached-password state, recent history. |

`command` is preferably an argv list (`["apt", "install", "foo"]`); a shell
string is also accepted (runs through `sh -c` — you approve exactly that string).

## Approval channels

1. **Matrix** — reply in the bot's room:
   - `yes` → approve
   - `no` → deny
   - `yes <password>` → approve and provide the sudo password in one step
   (English and German keywords understood: `ja`, `nein`, `ok`, `abort`, …)
2. **Terminal CLI** (works even if Matrix is down):
   ```sh
   python3 mcp_server.py status                 # pending requests + health
   python3 mcp_server.py approve last [password]
   python3 mcp_server.py deny last
   python3 mcp_server.py history -n 10
   ```

## Flow

```
agent ── sudo_run(cmd, reason) ──▶ server
                                      │ 1. denylist check (instant refusal)
                                      │ 2. POST /webhook  ──▶ your Matrix room
                                      │ 3. notify-send (desktop)
                                      │ 4. poll for decision (you: yes/no/yes <pw>)
                                      ▼
                              approved?
                              ├─ no  → {ok:false, status:"denied"}
                              └─ yes → sudo -n            (no password needed)
                                       sudo -S <pw>       (password from reply/cache)
                                       → {ok, exit_code, stdout, stderr}
```

If the command was approved but `sudo -n` says a password is required and none
was given, the server asks one follow-up question in Matrix
(`Send the password now (or 'no' to abort)`).

## Security model

- **Every run requires an explicit human decision.** Nothing is auto-approved.
- **Denylist** (`denylist` in `config.json`): substring patterns that are
  refused instantly without asking (defaults block `mkfs`, `dd if=`,
  fork bombs, `rm -rf /`, raw disk writes, …).
- **Passwords are never written to disk.** The decision file is deleted
  immediately after use; history only records a `password_provided` boolean.
- A password that actually worked may be held **in server memory** for
  `password_ttl_s` seconds (default 300, set `0` to never cache).
- State lives in `~/.local/state/interactivesudo/` (requests, `history.jsonl`,
  all `0600`).
- The bot API key lives in `secrets/api_key` (`0600`, git-ignored).

## Setup (already done on this machine)

- `~/projects/InteractiveSudoMCP/` — this project
  - `.venv` — Python venv with `mcp` (pinned `<2`, FastMCP) + `httpx`
  - `mcp_server.py` — the whole server (MCP + CLI)
  - `config.json` — runtime settings
  - `secrets/api_key` — MatrixWebhooker api_key of bot `mybot`
- Registered in `~/.config/opencode/opencode.json` under
  `mcp.servers.sudo` (backup of the previous config: `opencode.json.bak-20261009`).

## Configuration (`config.json`)

| Key | Default | Meaning |
|---|---|---|
| `webhooker_url` | `http://localhost:8080` | MatrixWebhooker base URL |
| `bot_name` | `mybot` | which webhooker bot sends the requests |
| `api_key_file` | `secrets/api_key` | file containing that bot's API key |
| `state_dir` | `~/.local/state/interactivesudo` | requests + history |
| `desktop_notify` | `true` | fire `notify-send` on requests |
| `wait_timeout_s` | `600` | how long to wait for yes/no |
| `password_ask_timeout_s` | `180` | how long to wait for a follow-up password |
| `command_timeout_s` | `300` | max runtime of the sudo command |
| `password_ttl_s` | `300` | in-memory password cache TTL (`0` = off) |
| `max_output_chars` | `20000` | stdout/stderr capture cap |
| `denylist` | see file | substrings refused without asking |

## Notes

- Run the server as your normal user; it escalates **only** through `sudo`
  and only after your approval — this replaces the `sudo opencode` pattern.
- A command that reads from stdin gets EOF after the password (standard
  `sudo -S` behavior).
- `sudo -n` is tried first when no password is available, so NOPASSWD
  sudoers rules keep working without prompting you.
