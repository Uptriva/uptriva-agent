# Uptriva Monitoring Agent

Open source monitoring agent for Uptriva. Collects system metrics (CPU, RAM, Disk, Network) and sends them to the Uptriva API.

## Features

- System metrics collection (CPU, RAM, Disk, Network)
- Local config storage (mode 0600, contains your agent token)
- TLS 1.2+ secure communication
- HMAC signature verification
- Self-updating support
- Cross-platform (Linux, macOS, Windows)

## Security

This agent is open source for transparency. You can review the code to verify:
- What data is collected
- How data is transmitted
- What is stored locally (agent token in cleartext JSON, mode 0600)
- No backdoors or malicious code

## Installation

### Linux/macOS

```bash
wget https://download.uptriva.com/agents/linux/amd64/uptriva-agent
chmod +x uptriva-agent
sudo mv uptriva-agent /usr/local/bin/uptriva-agent
```

### Windows

Download the latest binary from [Releases](https://github.com/uptriva/uptriva-agent/releases) and place it in your PATH.

## Usage

### First-time setup

```bash
uptriva-agent --token YOUR_TOKEN --api https://api.uptriva.com
```

The agent will perform a handshake with the API and store its session token in a local config file (agent_config.json, mode 0600).

### Running

```bash
uptriva-agent
```

The agent will read its config and start sending metrics.

### Optional metrics endpoint

```bash
uptriva-agent --token YOUR_TOKEN --api https://api.uptriva.com --port 8080
```

This starts a local metrics endpoint on `http://127.0.0.1:8080/metrics` (protected by the agent session token).

## Configuration

The agent stores configuration in `agent_config.json` in its working directory.

### Linux / macOS (installed via setup script)

- Config file: `/etc/uptriva/agent_config.json`
- Binary: `/usr/local/bin/uptriva-agent`
- Working directory: `/etc/uptriva`

### Windows

- Default binary: `C:\Program Files\Uptriva\uptriva-agent.exe`
- Config file: `agent_config.json` in the working directory from which the agent is started

### Config fields

```json
{
  "api_url": "https://api.uptriva.com",
  "token": "...",
  "agent_id": "...",
  "interval": 30,
  "port": 0,
  "auto_update_enabled": true,
  "auto_update_interval_minutes": 30,
  "watch_services": [],
  "security_events_enabled": false,
  "package_monitoring_enabled": false,
  "disable_remote_commands": false
}
```

- `interval` — metric collection interval in seconds (minimum: 15)
- `port` — optional local metrics endpoint on `http://127.0.0.1:{port}/metrics`
- `auto_update_enabled` — enable/disable automatic self-updates
- `auto_update_interval_minutes` — how often to check for updates
- `watch_services` — process names to watch; exits/recoveries emit `agent.process_exit`/`agent.process_recovered` events
- `security_events_enabled` — **add-on, default off** (Linux only): reports failed SSH/sudo authentications from the systemd journal as `agent.auth_failed` events. Requires the agent to have journal read access (root or `systemd-journal` group). Event messages include the raw log line, which may contain usernames and source IPs.
- `package_monitoring_enabled` — **add-on, default off** (Linux only): probes pending package updates every 30 minutes via `apt`/`dnf`/`yum`/`checkupdates` and emits `agent.pkg_updates_available`/`agent.pkg_updates_cleared` events
- `disable_remote_commands` — disables the remote command channel entirely (`restart_service`, `exec_script`, `collect_diagnostics` stay queued server-side but are never executed)

Toggles can also be set via CLI flags (persisted to the config) or environment variables:

```bash
uptriva-agent --security-events --package-monitoring   # enable
uptriva-agent --no-security-events                     # disable
uptriva-agent --no-remote-commands                     # disable remote exec
```

```bash
AGENT_SECURITY_EVENTS=true AGENT_PKG_MONITORING=true uptriva-agent
```

To avoid exposing the token in the process list, `AGENT_TOKEN` can be used instead of `--token`.

After editing the config, restart the agent:

```bash
sudo systemctl restart uptriva-agent
```

## Metrics Collected

- CPU Usage (%)
- RAM Usage (%)
- Disk Usage (%)
- Network In (bytes)
- Network Out (bytes)
- Running Processes (list)

## Trust model

Things you should know before running this on your servers:

- **Self-update is on by default.** The agent periodically replaces its binary from the Uptriva download server. Official releases are verified against an ed25519-signed manifest; self-built binaries skip signature verification unless you set `AGENT_RELEASE_PUBKEY`. Disable with `AGENT_DISABLE_UPDATE=true`.
- **Remote commands are off by default.** Enabling them lets the platform restart services, reboot the host, update packages, or run scripts (`exec_script` needs an extra flag). Review `cmd/commands.go` before opting in.
- **What leaves the host:** system metrics, process names, listening ports, systemd units, and host identity. Opt-in features can additionally send journal lines, SSH/sudo events, k8s pod log tails, and file-change events. Monitor check results may include credentials the platform assigns to this agent.
- **Your token is stored in cleartext** in `agent_config.json` (mode 0600). Protect the file accordingly.

## Building from source

```bash
go build -o uptriva-agent ./cmd
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
