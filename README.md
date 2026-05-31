# Luminet

> AI-Powered Local-First WiFi Management System for macOS.

Luminet turns a Mac into a controlled, observable, local-first WiFi management layer. It wraps macOS Internet Sharing with safer commands, hardened guest-mode planning, local device visibility, password rotation, security posture checks, and a protected dashboard.

It is built for people who want local infrastructure they can understand, inspect, and recover without depending on a cloud router dashboard.

## Why Luminet

Most hotspot tools are either too simple or too opaque. Luminet takes a different path:

- local-first by default
- explicit dry-runs before live changes
- readable JSON config
- reversible network mutations
- guest isolation planning through managed `pf` anchors
- dashboard controls that stay gated unless you intentionally unlock them

Luminet is not trying to be an enterprise access point. It is a practical control layer over what macOS actually exposes.

## Features

- Main and Guest profile switching with `./bin/hotspot switch main|guest`
- Clear staged-vs-live SSID status reporting
- macOS Internet Sharing configure/start/stop wrappers with confirmation tokens
- Interface-source mode for real AP/DHCP/client validation
- Loopback-source mode scaffolding for local-only experiments
- Guest profile dry-run with NAT preview, firewall preview, pre-flight checks, and rollback plan
- Hardened guest firewall plan through a managed `pf` anchor
- Device discovery from DHCP leases and ARP evidence
- Known-device inventory and unknown-device alerting
- Security posture report for passwords, config permissions, dashboard settings, and anomalies
- Main, Guest, and dashboard password rotation with PBKDF2 dashboard hashing
- Lockdown Mode with reversible macOS service state snapshots
- Emergency reset command for recovery
- Dependency-light local dashboard with form login, signed sessions, timeout, rate limiting, failed-login lockout, and auth logging
- Safe dashboard switch buttons that stage config only and do not silently mutate live networking

## Screenshots

Screenshots are intentionally placeholders until the first public release assets are captured.

### Dashboard overview

![Dashboard overview placeholder](docs/screenshots/dashboard-overview.png)

### Network switch panel

![Network switch placeholder](docs/screenshots/network-switch.png)

### Security status

![Security status placeholder](docs/screenshots/security-status.png)

### Guest dry-run plan

![Guest dry-run placeholder](docs/screenshots/guest-dry-run.png)

## Project layout

```text
.
├── bin/
│   ├── hotspot                    # CLI wrapper
│   ├── emergency-network-reset    # gated recovery command
│   └── sudo-askpass               # macOS sudo prompt helper
├── config/
│   ├── hotspot.json               # local runtime config, chmod 600
│   └── known_devices.json         # learned device inventory
├── scripts/
│   ├── hotspot.py                 # core CLI implementation
│   ├── dashboard.py               # local dashboard
│   └── hotspot_nl.py              # natural-language helper wrapper
├── docs/
├── logs/
└── SECURITY.md
```

## Installation

### Requirements

- macOS with Internet Sharing support
- Python 3 from the system or Xcode command-line tools
- Administrator access for live network changes
- WiFi hardware capable of macOS Internet Sharing

### Clone

```bash
git clone https://github.com/officialbrandonsandoval-source/luminet.git
cd luminet
```

If you are working from the current local project path:

```bash
cd /Users/brandonsandoval/Projects/local-hotspot
```

### Prepare config

The real runtime config can contain WiFi passwords, dashboard hashes, known interfaces, and local paths. It is intentionally ignored by git. Start from the sanitized example:

```bash
cp config/hotspot.example.json config/hotspot.json
chmod 600 config/hotspot.json
chmod +x bin/hotspot bin/emergency-network-reset bin/sudo-askpass
```

Then edit `config/hotspot.json` for your interfaces and rotate local passwords before live use.

### Check the plan

```bash
./bin/hotspot plan
./bin/hotspot status
./bin/hotspot security status
```

## Usage

### Show status

```bash
./bin/hotspot status
```

Status shows both the staged profile and the currently broadcasting SSID when that can be inferred from macOS NAT/bridge evidence.

### Switch between Main and Guest profiles

```bash
./bin/hotspot switch main
./bin/hotspot switch guest
```

This stages config only. It does not apply NAT, load firewall rules, or restart Internet Sharing.

To apply the staged profile live from this local project, use the explicit confirmation flow:

```bash
SUDO_ASKPASS=/Users/brandonsandoval/Projects/local-hotspot/bin/sudo-askpass ./bin/hotspot configure --apply --confirm CONFIGURE
SUDO_ASKPASS=/Users/brandonsandoval/Projects/local-hotspot/bin/sudo-askpass ./bin/hotspot start --apply --confirm ENABLE
```

For Guest mode, review and apply the firewall separately:

```bash
./bin/hotspot guest test
./bin/hotspot firewall plan
SUDO_ASKPASS=/Users/brandonsandoval/Projects/local-hotspot/bin/sudo-askpass ./bin/hotspot firewall apply --apply --confirm FIREWALL
```

### Open System Settings fallback

macOS may reject direct `launchctl` control even when the prepared config is valid. If that happens, use:

```bash
./bin/hotspot open-settings
```

Then toggle Internet Sharing manually and verify with:

```bash
./bin/hotspot status
./bin/hotspot devices --json
```

### Run the dashboard

```bash
./bin/hotspot dashboard
```

The dashboard binds to the active Internet Sharing bridge when available, then falls back to localhost. Live dashboard controls are disabled by default. The dashboard is for visibility and safe staging unless you explicitly enable real controls in config.

### Emergency reset

Dry-run first:

```bash
./bin/emergency-network-reset
```

Apply only when you intentionally want recovery:

```bash
SUDO_ASKPASS=/Users/brandonsandoval/Projects/local-hotspot/bin/sudo-askpass ./bin/emergency-network-reset --apply --confirm RESET
```

## Local-first philosophy

Luminet treats the Mac as the control plane.

- Config lives locally.
- Logs live locally.
- Passwords are generated locally.
- Dashboard auth is local.
- Recovery is local.
- Internet is useful, but not the foundation of the system.

The project is designed so a user can inspect every change before it touches live networking. Dry-runs are first-class. Confirmation tokens are intentional friction. The goal is reliable local control, not cloud dependency.

## Current limitations

### macOS single-SSID limitation

macOS Internet Sharing can broadcast only one hotspot SSID at a time on this host. Luminet Main and Guest are switchable profiles, not simultaneous networks.

That means:

- `Luminet` and `Luminet-Guest` cannot both be live at the same time through built-in Internet Sharing.
- `./bin/hotspot switch guest` stages Guest.
- `./bin/hotspot switch main` stages Main.
- Internet Sharing must be restarted or toggled before the staged SSID becomes the live broadcast.

### Guest isolation is best-effort

Guest hardening uses macOS `pf` at the IP layer. It can block traffic that traverses the host packet filter, but it cannot guarantee enterprise-grade WiFi layer-2 client isolation.

For high-assurance guest isolation, use dedicated router/AP hardware or a router OS designed for multi-SSID VLAN isolation.

### macOS automation gaps

macOS does not provide a stable public CLI for every Internet Sharing setting. Luminet can prepare config, inspect state, and try service control, but System Settings may still be required on some macOS versions.

### Interface names vary

Do not assume WiFi is `en0`. On some Mac Studio systems, Ethernet is `en0` and WiFi is `en1`.

## Security overview

Luminet is designed around explicit control and recoverability.

- Config file is chmod `600`
- Dashboard password is stored as PBKDF2-SHA256 hash
- Dashboard sessions are signed random tokens
- Sessions expire after five minutes of inactivity by default
- Login attempts are logged to `logs/dashboard-auth.jsonl`
- Failed login lockout is enforced per client IP
- Real dashboard controls are disabled by default
- Live CLI mutations require exact confirmation tokens
- Guest firewall rules use a managed anchor instead of global `pf` edits
- Emergency reset can stop sharing, flush the managed anchor, remove managed loopback aliases, and restore service state after Lockdown Mode

Important: do not publish real local passwords, dashboard hashes from a private deployment, MAC addresses, DHCP leases, or logs from a personal network.

## Roadmap

- Capture public dashboard screenshots and terminal demos
- Add an installer/bootstrap command
- Add automated config migration from private deployments to sanitized open-source defaults
- Add richer dashboard API responses
- Add optional HTTPS setup helper for the dashboard
- Add exportable diagnostics bundle with secret redaction
- Add clearer profile state machine tests
- Add loopback/local-only mode validation guide
- Add hardware-router integration notes for real VLAN guest isolation
- Add launchd service plist for supervised dashboard startup

## Contributing

Contributions are welcome. Read `CONTRIBUTING.md` first.

High-priority contributions:

- macOS compatibility reports
- safer state detection
- better dashboard UX
- stronger tests around config migration and profile switching
- documentation for router/AP integrations

## License

MIT. See `LICENSE`.
