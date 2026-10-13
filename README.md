# Uptriva Monitoring Agent

Open source monitoring agent for Uptriva. Collects system metrics (CPU, RAM, Disk, Network) and sends them to the Uptriva API.

## Features

- System metrics collection (CPU, RAM, Disk, Network)
- Encrypted configuration storage
- TLS 1.2+ secure communication
- HMAC signature verification
- Self-updating support
- Cross-platform (Linux, macOS, Windows)

## Security

This agent is open source for transparency. You can review the code to verify:
- What data is collected
- How data is transmitted
- How configuration is encrypted
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

The agent will perform a handshake with the API and store an encrypted configuration file.

### Running

```bash
uptriva-agent
```

The agent will read the encrypted configuration and start sending metrics.

### Optional metrics endpoint

```bash
uptriva-agent --token YOUR_TOKEN --api https://api.uptriva.com --port 8080
```

This starts a local metrics endpoint on `http://127.0.0.1:8080/metrics` (protected by API key).

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

## Building from source

```bash
go build -o uptriva-agent cmd/main.go
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
