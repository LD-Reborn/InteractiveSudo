#!/usr/bin/env bash
# Install/upgrade the root daemon. This is a deliberate HUMAN sudo action:
# run it yourself in a terminal. The agent must never run this.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
test -f "$DIR/mcp_server.py" || { echo "run from the project dir"; exit 1; }

echo "→ deploying daemon code (root-owned, so the agent cannot tamper with it)"
sudo install -d -m 0755 /usr/local/lib/interactivesudo
sudo install -m 0755 "$DIR/mcp_server.py" /usr/local/lib/interactivesudo/mcp_server.py

echo "→ config + api key in /etc/interactivesudo (created once, then preserved)"
sudo install -d -m 0750 /etc/interactivesudo
if [ ! -f /etc/interactivesudo/config.json ]; then
  sudo install -m 0640 "$DIR/daemon_config.example.json" /etc/interactivesudo/config.json
  echo "  created /etc/interactivesudo/config.json — review it (sudoedit)"
fi
if [ ! -f /etc/interactivesudo/api_key ]; then
  if [ -f "$DIR/secrets/api_key" ]; then
    sudo install -m 0600 "$DIR/secrets/api_key" /etc/interactivesudo/api_key
    echo "  imported secrets/api_key → /etc/interactivesudo/api_key"
    echo "  now DELETE the project copy (it may be in backups/sync): rm secrets/api_key"
    echo "  and rotate the key in MatrixWebhooker, then update the /etc copy."
  else
    echo "  !! no secrets/api_key found — put the webhooker bot key there:"
    echo "     sudo install -m 0600 /dev/null /etc/interactivesudo/api_key && sudoedit /etc/interactivesudo/api_key"
  fi
fi

echo "→ systemd unit"
sudo install -m 0644 "$DIR/interactivesudo.service" /etc/systemd/system/interactivesudo.service
sudo systemctl daemon-reload
sudo systemctl enable interactivesudo
sudo systemctl restart interactivesudo
sleep 1
systemctl is-active interactivesudo && echo "✓ daemon running" || {
  echo "✗ daemon failed to start:"; sudo journalctl -u interactivesudo -n 20 --no-pager; exit 1; }
