#!/bin/bash
set -euo pipefail

RELEASE_PUBKEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5RGhhAJQ+XQxodvhbyL67zYk0+xCYXQXyGVuxJZ0jDE=
-----END PUBLIC KEY-----'

TOKEN=""
ENROLL_TOKEN=""
CHANNEL="stable"
ALLOW_UNSIGNED=0
for i in "$@"; do
  case $i in
    --token=*)
      TOKEN="${i#*=}"
      ;;
    --enroll-token=*)
      ENROLL_TOKEN="${i#*=}"
      ;;
    --channel=*)
      CHANNEL="${i#*=}"
      ;;
    --allow-unsigned)
      ALLOW_UNSIGNED=1
      ;;
  esac
done
TOKEN="${TOKEN:-${AGENT_TOKEN:-}}"
ENROLL_TOKEN="${ENROLL_TOKEN:-${AGENT_ENROLL_TOKEN:-}}"

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

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
  RELEASES_JSON=$(curl -fsSL -m 15 "https://api.github.com/repos/Uptriva/uptriva-agent/releases?per_page=15" 2>/dev/null || true)
  BETA_TAG=$(printf '%s' "$RELEASES_JSON" | tr -d ' \n\t' | sed 's/},{/}\n{/g' \
    | grep '"prerelease":true' | head -n1 \
    | sed -n 's/.*"tag_name":"\([^"]*\)".*/\1/p' || true)
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
else
  echo "Unsupported OS: $OS"
  exit 1
fi

if [ -n "$ENROLL_TOKEN" ]; then
  HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
  AGENT_TOKEN_CFG=""
  for CFG in "/etc/uptriva/agent_config.json" "/etc/shxrk/agent_config.json" "$HOME/.uptriva/agent_config.json" "$HOME/.shxrk/agent_config.json"; do
    if [ -f "$CFG" ]; then
      AGENT_TOKEN_CFG=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$CFG" | head -n1)
      [ -n "$AGENT_TOKEN_CFG" ] && break
    fi
  done
  echo "Enrolling agent with enrollment token..."
  PAYLOAD_FILE=$(mktemp) && chmod 600 "$PAYLOAD_FILE"
  printf '{"token":"%s","hostname":"%s","agent_token":"%s"}' \
    "$(json_escape "$ENROLL_TOKEN")" "$(json_escape "$HOSTNAME")" "$(json_escape "$AGENT_TOKEN_CFG")" > "$PAYLOAD_FILE"
  RESP=$(curl -sS -X POST "$API_BASE/api/v1/uptime/agents/enroll" -H "Content-Type: application/json" -d @"$PAYLOAD_FILE" || true)
  rm -f "$PAYLOAD_FILE"
  TOKEN=$(printf '%s' "$RESP" | sed -n 's/.*"agent_token":"\([^"]*\)".*/\1/p')
  if [ -z "$TOKEN" ]; then
    echo "Enrollment failed: $RESP"
    exit 1
  fi
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

TMP_BIN=$(mktemp /tmp/uptriva-agent.XXXXXX) || { echo "Failed to create temp file"; exit 1; }
trap 'rm -f "$TMP_BIN"' EXIT

echo "Downloading monitoring agent for ${OS}/${ARCH}..."
if ! curl -fsSL -o "$TMP_BIN" "$GH_BASE/uptriva-agent-${OS}-${ARCH}" 2>/dev/null; then
  echo "Failed to download agent binary for ${OS}/${ARCH}"
  exit 1
fi

echo "Fetching and verifying release manifest..."
MANIFEST_FILE=$(mktemp) && chmod 600 "$MANIFEST_FILE"
if ! curl -fsSL -o "$MANIFEST_FILE" "$GH_BASE/manifest.json" 2>/dev/null; then
  echo "Failed to fetch release manifest"
  rm -f "$MANIFEST_FILE"
  exit 1
fi
MANIFEST=$(cat "$MANIFEST_FILE")

SIG_HEX=$(printf '%s' "$MANIFEST" | tr -d ' \t\n' | sed -n 's/.*"signature":"\([0-9a-fA-F]*\)".*/\1/p')
if [ -z "$SIG_HEX" ]; then
  if [ "$ALLOW_UNSIGNED" = "1" ]; then
    echo "WARNING: manifest is unsigned; continuing because --allow-unsigned was given"
  else
    echo "Error: release manifest is unsigned. Refusing to install (pass --allow-unsigned to override)."
    rm -f "$MANIFEST_FILE"
    exit 1
  fi
else
  PAYLOAD=$(printf '%s' "$MANIFEST" | tr -d ' \t\n' \
    | sed 's/,"key_id":"[0-9a-fA-F]*"//; s/,"signature":"[0-9a-fA-F]*"//')
  PUBKEY_FILE=$(mktemp) && chmod 600 "$PUBKEY_FILE"
  SIG_FILE=$(mktemp) && chmod 600 "$SIG_FILE"
  PAYLOAD_FILE=$(mktemp) && chmod 600 "$PAYLOAD_FILE"
  printf '%s' "$RELEASE_PUBKEY_PEM" > "$PUBKEY_FILE"
  if command -v xxd >/dev/null 2>&1; then
    printf '%s' "$SIG_HEX" | xxd -r -p > "$SIG_FILE"
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s' "$SIG_HEX" | python3 -c 'import sys,binascii;sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read()))' > "$SIG_FILE"
  elif command -v perl >/dev/null 2>&1; then
    printf '%s' "$SIG_HEX" | perl -ne 'print pack("H*", $_)' > "$SIG_FILE"
  else
    echo "Error: need xxd, python3, or perl to decode the manifest signature"
    rm -f "$PUBKEY_FILE" "$SIG_FILE" "$PAYLOAD_FILE" "$MANIFEST_FILE"
    exit 1
  fi
  printf '%s' "$PAYLOAD" > "$PAYLOAD_FILE"
  VERIFIED=0
  if openssl pkeyutl -verify -rawin -pubin -inkey "$PUBKEY_FILE" -sigfile "$SIG_FILE" -in "$PAYLOAD_FILE" >/dev/null 2>&1; then
    VERIFIED=1
  elif command -v python3 >/dev/null 2>&1 && python3 - "$PUBKEY_FILE" "$SIG_FILE" "$PAYLOAD_FILE" <<'PYEOF' 2>/dev/null
import sys, hashlib
def read_pem(p):
    import base64, re
    return base64.b64decode(re.sub(r'-----\w+ PUBLIC KEY-----', '', open(p).read()).strip())[-32:]
q = 2**255 - 19
def inv(x): return pow(x, q - 2, q)
d = -121665 * inv(121666) % q
I = pow(2, (q - 1) // 4, q)
def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0: x = x * I % q
    if x % 2 != 0: x = q - x
    return x
By = 4 * inv(5) % q
Bx = xrecover(By)
B = (Bx, By)
def edwards_add(P, Q):
    x1, y1 = P; x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2) % q
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2) % q
    return (x3, y3)
def scalarmult(P, e):
    Q = (0, 1)
    while e > 0:
        if e & 1: Q = edwards_add(Q, P)
        P = edwards_add(P, P)
        e >>= 1
    return Q
def decodepoint(s):
    y = int.from_bytes(s, 'little') & ((1 << 255) - 1)
    x = xrecover(y)
    if bool(x & 1) != bool(s[31] & 0x80): x = q - x
    if (y * y - x * x - 1 - d * x * x * y * y) % q != 0:
        raise ValueError('bad point')
    return (x, y)
pk = read_pem(sys.argv[1])
sig = open(sys.argv[2], 'rb').read()
msg = open(sys.argv[3], 'rb').read()
if len(sig) != 64: sys.exit(1)
R = decodepoint(sig[:32]); S = int.from_bytes(sig[32:], 'little'); A = decodepoint(pk)
h = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), 'little')
sys.exit(0 if scalarmult(B, S) == edwards_add(R, scalarmult(A, h)) else 1)
PYEOF
  then
    VERIFIED=1
  fi
  rm -f "$PUBKEY_FILE" "$SIG_FILE" "$PAYLOAD_FILE" "$MANIFEST_FILE"
  if [ "$VERIFIED" != "1" ]; then
    echo "Error: release manifest signature verification failed. Refusing to install."
    exit 1
  fi
  echo "Manifest signature verified"
fi

EXPECTED=$(printf '%s' "$MANIFEST" | tr -d ' \t\n' | sed -n "s/.*\"${OS}\/${ARCH}\":{[^}]*\"checksum\":\"\([a-fA-F0-9]*\)\".*/\1/p")
if [ -z "$EXPECTED" ]; then
  echo "No checksum for ${OS}/${ARCH} found in release manifest"
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMP_BIN" | cut -d' ' -f1)
elif command -v sha256 >/dev/null 2>&1; then
  ACTUAL=$(sha256 -q "$TMP_BIN")
else
  ACTUAL=$(shasum -a 256 "$TMP_BIN" | cut -d' ' -f1)
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch - refusing to install downloaded binary"
  exit 1
fi
echo "Checksum verified"

$SUDO tee "$BIN_DIR/.uptriva-agent.new" < "$TMP_BIN" > /dev/null
$SUDO chmod 0755 "$BIN_DIR/.uptriva-agent.new"
$SUDO mv -f "$BIN_DIR/.uptriva-agent.new" "$BIN_DIR/uptriva-agent"
rm -f "$TMP_BIN"
trap - EXIT

if [ -n "$TOKEN" ]; then
  echo "Registering agent with token..."
  cd "$CONFIG_DIR" || exit 1
  $SUDO rm -f "$CONFIG_DIR/agent_config.json"
  $SUDO env AGENT_TOKEN="$TOKEN" "$BIN_DIR/uptriva-agent" &
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

if [ "$CHANNEL" = "beta" ] && [ -f "$CONFIG_DIR/agent_config.json" ]; then
  if grep -q '"beta_channel"' "$CONFIG_DIR/agent_config.json"; then
    $SUDO sed -i.bak 's/"beta_channel":[^,}]*/"beta_channel":true/' "$CONFIG_DIR/agent_config.json" 2>/dev/null || \
      $SUDO sed -i '' 's/"beta_channel":[^,}]*/"beta_channel":true/' "$CONFIG_DIR/agent_config.json"
  else
    $SUDO sed -i.bak 's/^{/"beta_channel":true,/' "$CONFIG_DIR/agent_config.json" 2>/dev/null || \
      $SUDO sed -i '' 's/^{/"beta_channel":true,/' "$CONFIG_DIR/agent_config.json"
  fi
  $SUDO rm -f "$CONFIG_DIR/agent_config.json.bak"
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
UMask=0077
PrivateTmp=true
ProtectHome=read-only
ProtectHostname=true
ProtectClock=true
ProtectKernelLogs=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true

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
