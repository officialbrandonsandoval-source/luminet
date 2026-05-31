# Getting Started with Luminet

Luminet is a local-first control layer for macOS Internet Sharing. It helps you inspect, stage, and safely operate a Mac-based hotspot without hiding the sharp edges of macOS networking.

This guide is written for first-time users.

## 1. Requirements

- macOS with Internet Sharing support
- Python 3 available at `/usr/bin/python3`
- Admin access for live network changes
- A WiFi interface that macOS can use for Internet Sharing
- An upstream network interface, usually Ethernet or another adapter

Luminet does not require a cloud account or hosted backend.

## 2. Install locally

```bash
git clone https://github.com/officialbrandonsandoval-source/luminet.git
cd luminet
./bin/install
```

The installer is intentionally conservative. It only:

- creates local runtime directories
- copies `config/hotspot.example.json` to `config/hotspot.json` if missing
- sets safe file permissions
- marks helper scripts executable
- validates Python and JSON syntax

It does not start Internet Sharing. It does not apply firewall rules. It does not change live network state.

## 3. Inspect your Mac interfaces

```bash
./bin/hotspot interfaces
```

Look for:

- the upstream interface that provides internet access
- the WiFi interface used for broadcasting

On some Macs, Ethernet is `en0` and WiFi is `en1`. Do not assume WiFi is always `en0`.

## 4. Edit local config

```bash
nano config/hotspot.json
```

Update at minimum:

- `upstream_interface`
- `wifi_interface`
- `main.ssid`
- `guest.ssid`

Keep `config/hotspot.json` private. It is ignored by git because it can contain local passwords, private interface choices, and security state.

## 5. Rotate passwords

Generate strong local passwords before live use:

```bash
./bin/hotspot rotate-password main --length 32 --show
./bin/hotspot rotate-password guest --length 32 --show
```

Store the generated passwords somewhere safe. Do not commit them.

## 6. Run safe checks

These commands do not make live network changes:

```bash
./bin/hotspot status
./bin/hotspot security status
./bin/hotspot guest test
./bin/hotspot firewall plan
```

Read the output before applying anything live.

## 7. Understand Main vs Guest

macOS Internet Sharing can broadcast only one hotspot SSID at a time on this host.

Luminet Main and Guest are switchable profiles, not simultaneous networks.

Use:

```bash
./bin/hotspot switch main
./bin/hotspot switch guest
```

Switching stages config only. To make a staged SSID live, Internet Sharing must be restarted or toggled in System Settings.

## 8. Live apply sequence

Only run this when you are ready to modify macOS Internet Sharing:

```bash
SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/hotspot configure --apply --confirm CONFIGURE
SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/hotspot start --apply --confirm ENABLE
```

For Guest mode, review firewall rules first:

```bash
./bin/hotspot guest test
./bin/hotspot firewall plan
SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/hotspot firewall apply --apply --confirm FIREWALL
```

If macOS rejects direct service control, open System Settings:

```bash
./bin/hotspot open-settings
```

Then toggle Internet Sharing manually and verify:

```bash
./bin/hotspot status
./bin/hotspot devices --json
```

## 9. Dashboard

Start the local dashboard:

```bash
./bin/hotspot dashboard
```

The dashboard is built for visibility and safe staging. Live controls are disabled by default through `allow_real_controls: false` in config.

## 10. Recovery

Dry-run emergency reset first:

```bash
./bin/emergency-network-reset
```

Apply only when recovery is needed:

```bash
SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/emergency-network-reset --apply --confirm RESET
```

## Current limitations

- macOS supports one Internet Sharing hotspot SSID at a time.
- Guest isolation is best-effort and uses macOS `pf` at the IP layer.
- High-assurance guest isolation requires dedicated router/AP hardware or VLAN-capable router software.
- Some macOS versions require manual System Settings toggles even after Luminet prepares config.
- Interface names vary by Mac model and adapter setup.

## Safe first success target

A good first milestone is not “full automation.” It is:

1. `./bin/install` passes.
2. `./bin/hotspot status` shows readable staged/live state.
3. `./bin/hotspot guest test` produces a rollback-aware dry-run.
4. Dashboard launches locally.
5. No live network mutation happens until you intentionally approve it.
