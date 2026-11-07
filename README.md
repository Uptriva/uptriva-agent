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

Download the latest binary from [Releases](https://github.com/Uptriva/uptriva-agent/releases) and place it in your PATH.

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
  "beta_channel": false,
  "accepted_privacy_policy": "1.0.0",
  "watch_services": [],
  "watch_files": [],
  "watch_certs": [],
  "security_events_enabled": false,
  "package_monitoring_enabled": false,
  "port_watch_enabled": false,
  "integrity_monitoring_enabled": false,
  "kernel_events_enabled": false,
  "cert_watch_enabled": false,
  "system_posture_enabled": false,
  "container_watch_enabled": false,
  "log_watch_enabled": false,
  "enable_remote_commands": false,
  "allow_exec_script": false,
  "disable_remote_commands": false
}
```

- `interval` — metric collection interval in seconds (minimum: 15)
- `port` — optional local metrics endpoint on `http://127.0.0.1:{port}/metrics`
- `auto_update_enabled` — enable/disable automatic self-updates
- `auto_update_interval_minutes` — how often to check for updates
- `beta_channel` — opt in to beta releases (see [Update channels](#update-channels))
- `accepted_privacy_policy` — privacy policy version the operator consented to; managed automatically via `-accept-privacy-policy`
- `watch_services` — process names to watch; exits/recoveries emit `agent.process_exit`/`agent.process_recovered` events
- `watch_files` — extra files added to the integrity watch list
- `watch_certs` — extra certificate/glob paths monitored by cert-watch

### Add-on event monitors (all default off)

These features emit agent events to the platform. Most require Linux and read access to system logs or package managers (root or appropriate group membership).

- `security_events_enabled` — reports failed SSH/sudo authentications from the systemd journal as `agent.auth_failed` events. Event messages include the raw log line, which may contain usernames and source IPs.
- `package_monitoring_enabled` — probes pending package updates every 30 minutes via `apt`/`dnf`/`yum`/`checkupdates` and emits `agent.pkg_updates_available`/`agent.pkg_updates_cleared` events
- `port_watch_enabled` — emits `agent.listener_opened`/`agent.listener_closed` when listening TCP/UDP ports appear or disappear
- `integrity_monitoring_enabled` — watches sensitive files (`/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`, `authorized_keys`, …) plus `watch_files` and emits `agent.integrity_file_added`/`agent.integrity_file_changed`/`agent.integrity_file_removed`
- `kernel_events_enabled` — tails the kernel ring buffer via `journalctl -k` and reports OOM kills, segfaults, storage errors, etc.
- `cert_watch_enabled` — monitors TLS certificate files (default globs cover `/etc/letsencrypt/live/*/cert.pem` and `/etc/ssl/localcerts/*`; extend via `watch_certs`) and emits `agent.cert_expiring`/`agent.cert_expired`/`agent.cert_renewed`/`agent.cert_removed`
- `system_posture_enabled` — emits `agent.reboot_required`/`agent.reboot_cleared` and `agent.firewall_active`/`agent.firewall_inactive` state changes
- `container_watch_enabled` — tracks Docker/Podman containers and emits `agent.container_started`/`agent.container_stopped`
- `log_watch_enabled` — tails the system journal (Linux) or `/var/log` files and matches log lines against built-in rules (failed SSH logins, OOM kills, segfaults, storage errors) plus optional server-pushed rules, emitting `agent.log_match` events

### Remote commands (default off)

- `enable_remote_commands` — enables the remote command channel (`restart_service`, `exec_script`, `collect_diagnostics`). `disable_remote_commands` force-disables it even if enabled elsewhere. `exec_script` additionally requires `allow_exec_script`.
- `allow_exec_script` — permits the `exec_script` remote command; off by default even when remote commands are enabled

Toggles can also be set via CLI flags (persisted to the config) or environment variables:

```bash
uptriva-agent --security-events --package-monitoring   # enable
uptriva-agent --no-security-events                     # disable
uptriva-agent --remote-commands                        # enable remote exec
uptriva-agent --allow-exec-script                      # also allow exec_script
uptriva-agent --no-remote-commands                     # disable remote exec
uptriva-agent --beta update                            # switch to beta channel (persisted)
```

```bash
AGENT_SECURITY_EVENTS=true AGENT_PKG_MONITORING=true uptriva-agent
AGENT_ENABLE_COMMANDS=true AGENT_ALLOW_EXEC_SCRIPT=true uptriva-agent
```

To avoid exposing the token in the process list, `AGENT_TOKEN` can be used instead of `--token`. The config file location can be overridden with `UPTRIVA_AGENT_CONFIG`.

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

## Update channels

The agent checks for updates by default every `auto_update_interval_minutes` minutes. Updates are delivered as an ed25519-signed manifest that lists per-platform binaries with SHA-256 checksums; the agent verifies the signature before downloading and installing.

- **Stable (default)** — the agent fetches the latest non-prerelease GitHub release from `Uptriva/uptriva-agent`, falling back to the Uptriva download server (`https://download.uptriva.com/manifest`) if GitHub is unreachable.
- **Beta** — set `beta_channel: true` in the config or pass `--beta`. The agent then follows the newest GitHub *prerelease* or `https://download.uptriva.com/manifest/beta`. Beta builds are published from the `beta` branch and are not promoted to stable automatically.
- The GitHub repository can be overridden with `AGENT_GITHUB_REPO=owner/name` (useful for mirrors or forks).

If a release changes the privacy policy version, the update pauses until an operator runs `uptriva-agent -accept-privacy-policy` to consent. The current policy is published at <https://uptriva.com/privacy>.

## Trust model

Things you should know before running this on your servers:

- **Self-update is on by default.** The agent periodically replaces its binary from GitHub Releases (falling back to the Uptriva download server). Official releases are verified against an ed25519-signed manifest; self-built binaries skip signature verification unless you set `AGENT_RELEASE_PUBKEY`. Disable with `AGENT_DISABLE_UPDATE=true`.
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
