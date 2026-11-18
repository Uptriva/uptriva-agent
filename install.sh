#!/bin/bash
TOKEN=""
ENROLL_TOKEN=""
CHANNEL="stable"
for i in "$@"; do
  case $i in
    --token=*)
      TOKEN="${i#*=}"
      shift
      ;;
    --enroll-token=*)
      ENROLL_TOKEN="${i#*=}"
      shift
      ;;
    --channel=*)
      CHANNEL="${i#*=}"
      shift
      ;;
  esac
done

API_BASE=""
for BASE in "https://api.uptriva.com" "https://api.shxrk.systems"; do
  if curl -fsS -m 10 -o /dev/null "$BASE/health" 2>/dev/null; then
    API_BASE="$BASE"
    break
  fi
done
if [ -z "$API_BASE" ]; then
  echo "Error: could not reach the monitoring API (tried api.uptriva.com and api.shxrk.systems)"
  exit 1
fi

GH_BASE="https://github.com/Uptriva/uptriva-agent/releases/latest/download"
if [ "$CHANNEL" = "beta" ]; then
  BETA_TAG=$(curl -fsSL -m 15 "https://api.github.com/repos/Uptriva/uptriva-agent/releases?per_page=15" 2>/dev/null \
    | grep -oE '"tag_name":"[^"]+"|"prerelease":(true|false)' \
    | paste - - \
    | sed -n 's/"tag_name":"\([^"]*\)".*"prerelease":true.*/\1/p' \
    | head -n1)
  if [ -z "$BETA_TAG" ]; then
    echo "Error: no beta release found for uptriva-agent"
    exit 1
  fi
  GH_BASE="https://github.com/Uptriva/uptriva-agent/releases/download/${BETA_TAG}"
  echo "Using beta release ${BETA_TAG}"
fi
if ! curl -fsSI -m 10 -o /dev/null "$GH_BASE/manifest.json" 2>/dev/null; then
  echo "Error: could not reach the agent release repository"
  exit 1
fi

if [ -n "$ENROLL_TOKEN" ]; then
  HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
  AGENT_TOKEN=""
  for CFG in "/etc/uptriva/agent_config.json" "/etc/shxrk/agent_config.json" "$HOME/.uptriva/agent_config.json" "$HOME/.shxrk/agent_config.json"; do
    if [ -f "$CFG" ]; then
      AGENT_TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$CFG" | head -n1)
      [ -n "$AGENT_TOKEN" ] && break
    fi
  done
  echo "Enrolling agent with enrollment token..."
  RESP=$(curl -sS -X POST "$API_BASE/api/v1/uptime/agents/enroll" -H "Content-Type: application/json" -d "{\"token\":\"$ENROLL_TOKEN\",\"hostname\":\"$HOSTNAME\",\"agent_token\":\"$AGENT_TOKEN\"}")
  TOKEN=$(echo "$RESP" | sed -n 's/.*"agent_token":"\([^"]*\)".*/\1/p')
  if [ -z "$TOKEN" ]; then
    echo "Enrollment failed: $RESP"
    exit 1
  fi
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

SUDO=""
if [ "$OS" = "darwin" ]; then
  BIN_DIR="$HOME/.local/bin"
  CONFIG_DIR="$HOME/.uptriva"
  LEGACY_CONFIG_DIR="$HOME/.shxrk"
  PLIST="$HOME/Library/LaunchAgents/com.uptriva.agent.plist"
  mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$HOME/Library/LaunchAgents"
elif [ "$OS" = "linux" ]; then
  BIN_DIR="/usr/local/bin"
  CONFIG_DIR="/etc/uptriva"
  LEGACY_CONFIG_DIR="/etc/shxrk"
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      SUDO="sudo"
    else
      echo "Error: root privileges are required on Linux. Re-run as root or install sudo."
      exit 1
    fi
  fi
  $SUDO mkdir -p "$CONFIG_DIR"
elif [ "$OS" = "freebsd" ]; then
  BIN_DIR="/usr/local/bin"
  CONFIG_DIR="/usr/local/etc/uptriva"
  LEGACY_CONFIG_DIR="/usr/local/etc/shxrk"
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      SUDO="sudo"
    else
      echo "Error: root privileges are required on FreeBSD. Re-run as root or install sudo."
      exit 1
    fi
  fi
  $SUDO mkdir -p "$CONFIG_DIR"
else
  echo "Unsupported OS: $OS"
  exit 1
fi

if [ "$OS" = "linux" ]; then
  for OLDUNIT in uptime-agent shxrk-agent; do
    if systemctl list-unit-files "${OLDUNIT}.service" 2>/dev/null | grep -q "${OLDUNIT}\.service" || [ -f "/etc/systemd/system/${OLDUNIT}.service" ]; then
      echo "Migrating legacy ${OLDUNIT} installation..."
      $SUDO systemctl stop "$OLDUNIT" 2>/dev/null || true
      $SUDO systemctl disable "$OLDUNIT" 2>/dev/null || true
      $SUDO rm -f "/etc/systemd/system/${OLDUNIT}.service" "$BIN_DIR/${OLDUNIT}"
      $SUDO systemctl daemon-reload
    fi
  done
elif [ "$OS" = "darwin" ]; then
  for OLD_PLIST in "$HOME/Library/LaunchAgents/systems.shxrk.agent.plist" "$HOME/Library/LaunchAgents/systems.shxrk.uptime-agent.plist"; do
    if [ -f "$OLD_PLIST" ]; then
      echo "Migrating legacy agent installation..."
      launchctl unload "$OLD_PLIST" 2>/dev/null || true
      rm -f "$OLD_PLIST"
    fi
  done
  rm -f "$BIN_DIR/shxrk-agent" "$BIN_DIR/uptime-agent" 2>/dev/null || true
fi

if [ ! -f "$CONFIG_DIR/agent_config.json" ] && [ -f "$LEGACY_CONFIG_DIR/agent_config.json" ]; then
  echo "Migrating existing agent configuration..."
  $SUDO cp -a "$LEGACY_CONFIG_DIR/." "$CONFIG_DIR/" 2>/dev/null || true
fi

if [ -z "$TOKEN" ]; then
  if [ -f "$CONFIG_DIR/agent_config.json" ]; then
    echo "Existing agent configuration found - reusing stored credentials"
  else
    echo "Error: --token or --enroll-token is required"
    exit 1
  fi
fi

echo "Downloading monitoring agent for ${OS}/${ARCH}..."
if ! $SUDO curl -fsSL -o "$BIN_DIR/uptriva-agent" "$GH_BASE/uptriva-agent-${OS}-${ARCH}" 2>/dev/null; then
  echo "Failed to download agent binary for ${OS}/${ARCH}"
  exit 1
fi

echo "Verifying checksum against release manifest..."
MANIFEST=$(curl -fsSL "$GH_BASE/manifest.json" 2>/dev/null) || { echo "Failed to fetch release manifest"; exit 1; }
EXPECTED=$(echo "$MANIFEST" | tr -d ' \t\n' | sed -n "s/.*\"${OS}\/${ARCH}\":{[^}]*\"checksum\":\"\([a-fA-F0-9]*\)\".*/\1/p")
if [ -z "$EXPECTED" ]; then
  echo "No checksum for ${OS}/${ARCH} found in release manifest"
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$BIN_DIR/uptriva-agent" | cut -d' ' -f1)
elif command -v sha256 >/dev/null 2>&1; then
  ACTUAL=$(sha256 -q "$BIN_DIR/uptriva-agent")
else
  ACTUAL=$(shasum -a 256 "$BIN_DIR/uptriva-agent" | cut -d' ' -f1)
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch - refusing to install downloaded binary"
  $SUDO rm -f "$BIN_DIR/uptriva-agent"
  exit 1
fi

$SUDO chmod +x "$BIN_DIR/uptriva-agent"

if [ -n "$TOKEN" ]; then
  echo "Registering agent with token..."
  cd "$CONFIG_DIR" || exit 1
  $SUDO rm -f "$CONFIG_DIR/agent_config.json"
  $SUDO "$BIN_DIR/uptriva-agent" --token="$TOKEN" &
  AGENT_PID=$!
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [ -f "$CONFIG_DIR/agent_config.json" ]; then
      break
    fi
    sleep 1
  done
  $SUDO kill "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
  if [ ! -f "$CONFIG_DIR/agent_config.json" ]; then
    echo "Failed to register agent. Check token validity."
    exit 1
  fi
elif [ ! -f "$CONFIG_DIR/agent_config.json" ]; then
  echo "No existing configuration found. Re-run with --token."
  exit 1
fi

if [ "$OS" = "darwin" ]; then
  echo "Creating LaunchAgent service..."
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.uptriva.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BIN_DIR}/uptriva-agent</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${CONFIG_DIR}</string>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${CONFIG_DIR}/agent.log</string>
  <key>StandardErrorPath</key>
  <string>${CONFIG_DIR}/agent.log</string>
</dict>
</plist>
EOF
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST"
  sleep 2
  if launchctl list | grep -q "com.uptriva.agent"; then
    echo "Uptriva agent successfully installed and started!"
  else
    echo "WARNING: agent service failed to start. Check: tail -50 $CONFIG_DIR/agent.log"
    exit 1
  fi
elif [ "$OS" = "freebsd" ]; then
  echo "Creating rc.d service..."
  $SUDO tee /usr/local/etc/rc.d/uptriva-agent > /dev/null <<'EOF'
#!/bin/sh
# PROVIDE: uptriva_agent
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown

name="uptriva_agent"
rcvar="${name}_enable"
command="/usr/local/bin/uptriva-agent"
uptriva_agent_chdir="/usr/local/etc/uptriva"
pidfile="/var/run/${name}.pid"
procname="${command}"
command_args=""

. /etc/rc.subr
run_rc_command "$1"
EOF
  $SUDO chmod +x /usr/local/etc/rc.d/uptriva-agent
  $SUDO sysrc uptriva_agent_enable=YES
  $SUDO service uptriva-agent start

  if $SUDO service uptriva-agent status >/dev/null 2>&1; then
    echo "Uptriva agent successfully installed and started!"
  else
    echo "WARNING: agent service failed to start. Check: service uptriva-agent status"
    exit 1
  fi
elif [ "$OS" = "linux" ]; then
  echo "Creating systemd service..."
  $SUDO tee /etc/systemd/system/uptriva-agent.service > /dev/null <<EOF
[Unit]
Description=Uptriva Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${BIN_DIR}/uptriva-agent
Restart=always
RestartSec=5
User=root
WorkingDirectory=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now uptriva-agent

  if $SUDO systemctl is-active --quiet uptriva-agent; then
    echo "Uptriva agent successfully installed and started!"
  else
    echo "WARNING: agent service failed to start. Check: journalctl -u uptriva-agent -n 50"
    exit 1
  fi
fi
