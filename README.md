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

The agent stores configuration in `agent_config.enc` (encrypted). Configuration includes:
- API URL
- API Key
- Agent ID
- Organization ID
- Check interval (default: 10 seconds)

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
