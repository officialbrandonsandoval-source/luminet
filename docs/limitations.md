# Luminet Limitations

Luminet is intentionally honest about what macOS Internet Sharing can and cannot do.

## One hotspot SSID at a time

macOS Internet Sharing can broadcast one hotspot SSID at a time from the host Mac.

Luminet's Main and Guest networks are switchable profiles. They are not simultaneous SSIDs.

When you run:

```bash
./bin/hotspot switch guest
```

Luminet stages the Guest profile in local config. To make the staged profile live, you must restart/toggle Internet Sharing through Luminet's explicit confirmation flow or macOS System Settings.

## Guest isolation is best-effort

Luminet can generate and apply hardened `pf` rules for Guest mode. Those rules are useful, but they are not the same as dedicated VLAN isolation on router/AP hardware.

Use dedicated networking hardware when you need high-assurance segmentation.

## macOS may require manual toggles

Some macOS versions reject direct Internet Sharing service control even when the underlying configuration is correct.

When that happens, Luminet can still prepare config, then you may need to run:

```bash
./bin/hotspot open-settings
```

Then toggle Internet Sharing manually in System Settings.

## Interface names vary

Do not assume Ethernet is always `en0` or WiFi is always `en1`.

Use:

```bash
./bin/hotspot interfaces
```

Then update `config/hotspot.json` for your Mac.

## Local dashboard is not a cloud control plane

The dashboard is local-first. It is designed for visibility and safe staged control from the hotspot network or localhost. It is not meant to be exposed to the public internet.

Keep `dashboard.allow_real_controls` disabled unless you fully understand the risk.

## Recovery still matters

Always dry-run recovery before live experiments:

```bash
./bin/emergency-network-reset
```

Only apply recovery with the explicit token:

```bash
SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/emergency-network-reset --apply --confirm RESET
```
