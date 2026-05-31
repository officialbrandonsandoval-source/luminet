# Contributing to Luminet

Thanks for helping improve Luminet.

Luminet manages local networking state, so contributions should favor safety, reversibility, and clear user warnings over clever automation.

## Ground rules

1. Dry-run first.
   - New live network behavior must include a non-mutating preview path.
   - Existing confirmation tokens must not be weakened.

2. Do not hide side effects.
   - Any command that writes system config, changes `pf`, starts/stops Internet Sharing, or disables services must be explicit.
   - Use exact confirmation tokens for live mutations.

3. Preserve local-first behavior.
   - No mandatory cloud services.
   - No telemetry by default.
   - No external calls for core functionality.

4. Protect secrets.
   - Do not commit real SSID passwords, dashboard hashes from a private deployment, MAC addresses, DHCP leases, auth logs, or personal network logs.
   - Keep generated config examples sanitized.

5. Be honest about macOS limits.
   - Main and Guest are switchable profiles, not simultaneous built-in Internet Sharing SSIDs.
   - Guest isolation through `pf` is best-effort and not enterprise WiFi VLAN isolation.

## Development checks

Run these before submitting a change:

```bash
python3 -m py_compile scripts/hotspot.py scripts/dashboard.py scripts/hotspot_nl.py
./bin/hotspot -h
./bin/hotspot switch -h
./bin/hotspot status
./bin/hotspot guest test
./bin/emergency-network-reset
```

Do not run live commands in tests unless you are intentionally testing on your own machine and understand the rollback path.

## Pull request checklist

- [ ] I ran syntax checks.
- [ ] I ran dry-run/status checks.
- [ ] I did not commit secrets or private logs.
- [ ] New live mutations require explicit confirmation.
- [ ] Documentation was updated for user-facing behavior.
- [ ] macOS limitations are stated clearly where relevant.

## Style

- Plain language.
- Clear warnings.
- Short commands.
- Prefer readable JSON and straightforward Python over clever abstractions.
