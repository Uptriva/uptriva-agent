#!/usr/bin/env bash
set -euo pipefail

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"

echo "Uptriva Agent Uninstaller"
echo "Detected OS: $OS"

if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    SUDO=""
  fi
else
  SUDO=""
fi

REMOVED=0

if [ "$OS" = "linux" ]; then
  for UNIT in uptriva-agent shxrk-agent uptime-agent; do
    if [ -f "/etc/systemd/system/${UNIT}.service" ] || systemctl list-unit-files "${UNIT}.service" 2>/dev/null | grep -q "${UNIT}\.service"; then
      echo "Stopping and removing systemd unit ${UNIT}.service"
      $SUDO systemctl stop "${UNIT}" 2>/dev/null || true
      $SUDO systemctl disable "${UNIT}" 2>/dev/null || true
      $SUDO rm -f "/etc/systemd/system/${UNIT}.service"
      REMOVED=1
    fi
  done
  $SUDO systemctl daemon-reload 2>/dev/null || true

  for BIN in uptriva-agent shxrk-agent uptime-agent; do
    for DIR in /usr/local/bin /usr/bin /bin; do
      if [ -f "${DIR}/${BIN}" ]; then
        echo "Removing binary ${DIR}/${BIN}"
        $SUDO rm -f "${DIR}/${BIN}"
        REMOVED=1
      fi
    done
  done

  for DIR in /etc/uptriva /etc/shxrk; do
    if [ -d "$DIR" ]; then
      echo "Removing config directory $DIR"
      $SUDO rm -rf "$DIR"
      REMOVED=1
    fi
  done

elif [ "$OS" = "darwin" ]; then
  for PLIST in com.uptriva.agent systems.shxrk.agent systems.shxrk.uptime-agent; do
    PLIST_PATH="$HOME/Library/LaunchAgents/${PLIST}.plist"
    if [ -f "$PLIST_PATH" ] || launchctl list 2>/dev/null | grep -q "${PLIST}"; then
      echo "Unloading and removing LaunchAgent ${PLIST}"
      launchctl bootout "gui/$(id -u)/${PLIST}" 2>/dev/null || launchctl unload "$PLIST_PATH" 2>/dev/null || true
      rm -f "$PLIST_PATH"
      REMOVED=1
    fi
  done

  for BIN in uptriva-agent shxrk-agent uptime-agent; do
    for DIR in "$HOME/.local/bin" /usr/local/bin; do
      if [ -f "${DIR}/${BIN}" ]; then
        echo "Removing binary ${DIR}/${BIN}"
        rm -f "${DIR}/${BIN}" 2>/dev/null || $SUDO rm -f "${DIR}/${BIN}"
        REMOVED=1
      fi
    done
  done

  for DIR in "$HOME/.uptriva" "$HOME/.shxrk"; do
    if [ -d "$DIR" ]; then
      echo "Removing config directory $DIR"
      rm -rf "$DIR"
      REMOVED=1
    fi
  done

else
  echo "Unsupported OS: $OS"
  exit 1
fi

if [ "$REMOVED" -eq 0 ]; then
  echo "No agent installation found."
else
  echo ""
  echo "Uninstall complete. The agent will stop reporting at the next heartbeat interval."
  echo "You can delete the agent entry in the Uptriva dashboard under Uptime > Agents."
fi
