## v1.3.8

- Fixed macOS fallback collectors not resolving `top`/`netstat` under launchd's minimal PATH (absolute paths now used)
- Fixed CPU idle parsing of `top` output (trailing space broke `%` stripping)

## v1.3.7

- macOS (darwin) support: LaunchAgent-based service install, user-level paths, no systemd dependency
- Fixed CPU and network metrics reporting 0 on macOS: native `/usr/bin/top`/`/usr/sbin/netstat` fallbacks when gopsutil collectors are unavailable in CGO-disabled builds
- Metric collector failures are now logged once instead of silently returning zero

## v1.3.4

- Game server monitor checks can now run on agents, including private and internal targets
- Supported query methods: A2S/Source Engine query (Rust, CS2, ARK, Valheim, custom), Minecraft status protocol, FiveM dynamic.json, generic REST endpoints, and TCP connect
- Check messages include live player counts (e.g. "12/40 players on de_dust2")

## v1.3.3

- No functional changes; rebuild/re-release

## v1.3.2

- New agent-executed monitor types: UDP port checks, SSL certificate expiry, domain expiry, Redis, SMTP STARTTLS
- Redis checks support password authentication and optional PING verification via monitor settings

## v1.3.1

- Self-update hardening: previous binary is kept as .bak and automatically restored if the new binary fails to report healthy metrics within 3 restarts
- Version comparison handles v-prefixed version strings correctly
- Fixed race condition in network rate counters between collectors and the local metrics handler
- Agent-executed HTTP checks honor the monitor verify_ssl setting and cap response body reads
- Metrics submission retries once after 10 seconds on transport errors

## v1.3.0

- Systemd unit monitoring: collects all service units and reports failed units
- Load average reporting (1m, 5m, 15m)
- System uptime reporting
- Detailed memory metrics (total, available, used, swap usage and percent)
- Per-disk usage details (all mounted partitions with sizes and percent)
- CPU core count reporting
- Enables server-side event rules: agent.systemd_unit_failed, agent.load_high, agent.swap_high

## v1.2.0

- Manifest-based update system with SHA256 checksum verification
- Privacy policy consent flow: updates that change the privacy policy require explicit acceptance
- New flags: -check-update, -accept-privacy-policy
- Atomic binary swap with backup on update
- Config stores accepted privacy policy version
