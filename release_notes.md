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
