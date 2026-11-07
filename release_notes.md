## v1.7.0

- Update channel now reads signed release manifests from GitHub Releases first, with the download server as fallback; beta channel maps to GitHub prereleases
- Release artifacts are published as GitHub release assets alongside the existing download-server upload, preparing the move to fully GitHub-hosted updates

## v1.6.2

- FreeBSD support in the one-liner installer — rc.d service, native /usr/local paths, sha256 -q checksums (OPNsense-ready)

## v1.6.1

- kube_deploy checks now report `degraded` on partial replica loss instead of `down`, so a single pod failing reads as a warning, not an outage

## v1.5.9

- kube_deploy checks now report per-pod metrics (name, phase, ready containers, restarts, node) so the dashboard can render a full workload view with replica counts and a pod table


## v1.5.8

- Kubernetes workload monitoring: kube_deploy checks now accept a `kind` setting (`deployment`, `statefulset`, `daemonset`), so StatefulSets (databases, KeyDB) and DaemonSets can be monitored for replica readiness instead of relying on pod IPs


## v1.4.1

- Security event detection on Linux (opt-in add-on): failed SSH/sudo authentications are collected from the systemd journal and emitted as `agent.auth_failed` events (up to 20 per batch, deduplicated server-side)
- Package update monitoring (opt-in add-on): pending system package updates are probed every 30 minutes (apt, dnf, yum, pacman-contrib `checkupdates`) and emitted as `agent.pkg_updates_available`/`agent.pkg_updates_cleared` events with update and security-update counts
- Both add-ons are off by default; enable via `--security-events` / `--package-monitoring`, `AGENT_SECURITY_EVENTS` / `AGENT_PKG_MONITORING`, or the `security_events_enabled` / `package_monitoring_enabled` config fields
- New command types for scheduled tasks and rules: `update_packages` (apt-get/dnf/yum/pacman/apk upgrade, brew, winget — 15-minute timeout, forces a fresh update probe afterwards) and `reboot_host` (acknowledged to the API before the machine goes down)
- New hardening switch `--no-remote-commands` / `disable_remote_commands` disables the remote command channel entirely
- Hardening: service names passed to `restart_service` are validated against a strict charset (closes PowerShell/flag injection), ping/whois check targets can no longer inject CLI flags, and `AGENT_TOKEN` can be used instead of `--token` to keep the token out of the process list
- No-op on non-Linux systems and on hosts without journalctl/package managers

## v1.3.9

- Remote command channel: agents poll `/agents/commands` every 15s and execute queued actions from event rules — `restart_service` (systemd/launchd/Windows Service), `exec_script` (120s timeout, output captured to result), `collect_diagnostics` (returns current metrics snapshot)
- Command results are acked back to the API and emitted as `agent.command_completed`/`agent.command_failed` events, so rules can react to command outcomes

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
