# ShxrkSystems Uptime Agent

Open source monitoring agent for ShxrkSystems Uptime. Collects system metrics (CPU, RAM, Disk, Network) and sends them to the ShxrkSystems API.

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
wget https://github.com/shxrksystems/uptime-agent/releases/latest/download/uptime-agent-linux-amd64
chmod +x uptime-agent-linux-amd64
sudo mv uptime-agent-linux-amd64 /usr/local/bin/uptime-agent
```

### Windows

Download the latest binary from [Releases](https://github.com/shxrksystems/uptime-agent/releases) and place it in your PATH.

## Usage

### First-time setup

```bash
uptime-agent --token YOUR_TOKEN --api https://api.shxrk.systems
```

The agent will perform a handshake with the API and store an encrypted configuration file.

### Running

```bash
uptime-agent
```

The agent will read the encrypted configuration and start sending metrics.

### Optional metrics endpoint

```bash
uptime-agent --token YOUR_TOKEN --api https://api.shxrk.systems --port 8080
```

This starts a local metrics endpoint on `http://127.0.0.1:8080/metrics` (protected by API key).

## Configuration

The agent stores configuration in `agent_config.json` in its working directory.

### Linux / macOS (installed via setup script)

- Config file: `/etc/shxrk/agent_config.json`
- Binary: `/usr/local/bin/uptime-agent`
- Working directory: `/etc/shxrk`

### Windows

- Default binary: `C:\Program Files\ShxrkSystems\uptime-agent.exe`
- Config file: `agent_config.json` in the working directory from which the agent is started

### Config fields

```json
{
  "api_url": "https://api.shxrk.systems",
  "token": "...",
  "agent_id": "...",
  "interval": 30,
  "port": 0,
  "auto_update_enabled": true,
  "auto_update_interval_minutes": 30
}
```

- `interval` — metric collection interval in seconds (minimum: 15)
- `port` — optional local metrics endpoint on `http://127.0.0.1:{port}/metrics`
- `auto_update_enabled` — enable/disable automatic self-updates
- `auto_update_interval_minutes` — how often to check for updates

After editing the config, restart the agent:

```bash
sudo systemctl restart uptime-agent
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
go build -o uptime-agent cmd/main.go
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
