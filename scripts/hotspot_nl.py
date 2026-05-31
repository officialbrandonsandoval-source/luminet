#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
HOTSPOT = PROJECT_DIR / "bin" / "hotspot"

SAFE = {
    "status": ["status"],
    "plan": ["plan"],
    "devices": ["devices"],
    "connected": ["devices"],
    "clients": ["devices"],
    "who is connected": ["devices"],
    "logs": ["logs", "--recent"],
    "history": ["logs", "--recent"],
    "recent logs": ["logs", "--recent"],
    "monitor once": ["monitor", "--once"],
    "monitor devices": ["monitor"],
    "watch devices": ["monitor"],
    "guest status": ["guest", "status"],
    "firewall plan": ["firewall", "plan"],
    "firewall status": ["firewall", "status"],
    "guest isolation plan": ["firewall", "plan"],
    "dashboard": ["dashboard"],
    "open dashboard": ["dashboard"],
    "start dashboard": ["dashboard"],
    "open settings": ["open-settings"],
    "settings": ["open-settings"],
    "generate guest password": ["generate-password", "--guest"],
    "new guest password": ["generate-password", "--guest"],
    "generate password": ["generate-password"],
    "new password": ["generate-password"],
    "loopback status": ["status"],
}

DANGEROUS = {
    "turn on": ( ["start"], "ENABLE" ),
    "start": ( ["start"], "ENABLE" ),
    "enable hotspot": ( ["start"], "ENABLE" ),
    "turn off": ( ["stop"], "DISABLE" ),
    "stop": ( ["stop"], "DISABLE" ),
    "disable hotspot": ( ["stop"], "DISABLE" ),
    "configure": ( ["configure"], "CONFIGURE" ),
    "setup loopback": ( ["setup-loopback"], "LOOPBACK" ),
    "create loopback": ( ["setup-loopback"], "LOOPBACK" ),
    "remove loopback": ( ["remove-loopback"], "REMOVE_LOOPBACK" ),
    "apply firewall": ( ["firewall", "apply"], "FIREWALL" ),
    "enable firewall": ( ["firewall", "apply"], "FIREWALL" ),
    "load guest isolation": ( ["firewall", "apply"], "FIREWALL" ),
    "remove firewall": ( ["firewall", "remove"], "FIREWALL_REMOVE" ),
    "disable firewall": ( ["firewall", "remove"], "FIREWALL_REMOVE" ),
}

PROFILE = {
    "enable guest": ["guest", "enable"],
    "turn on guest": ["guest", "enable"],
    "guest on": ["guest", "enable"],
    "disable guest": ["guest", "disable"],
    "turn off guest": ["guest", "disable"],
    "guest off": ["guest", "disable"],
    "main network": ["guest", "disable"],
}


def classify(text):
    t = text.lower().strip()
    for key in sorted(DANGEROUS, key=len, reverse=True):
        if key in t:
            return DANGEROUS[key][0], True, DANGEROUS[key][1]
    for key in sorted(PROFILE, key=len, reverse=True):
        if key in t:
            return PROFILE[key], False, ""
    for key in sorted(SAFE, key=len, reverse=True):
        if key in t:
            return SAFE[key], False, ""
    if "ssid" in t or "network name" in t:
        return None, False, ""
    return ["status"], False, ""


def main():
    ap = argparse.ArgumentParser(description="Natural-language wrapper for Luminet hotspot control")
    ap.add_argument("text", nargs="+", help="Natural language command")
    ap.add_argument("--apply", action="store_true", help="Allow impactful commands when paired with --confirm")
    ap.add_argument("--confirm", default="", help="ENABLE, DISABLE, CONFIGURE, LOOPBACK, REMOVE_LOOPBACK, FIREWALL, or FIREWALL_REMOVE")
    args = ap.parse_args()
    text = " ".join(args.text)
    cmd, dangerous, expected = classify(text)
    if cmd is None:
        raise SystemExit("SSID/password changes require explicit CLI: ./bin/hotspot set-config --ssid NAME or --guest-ssid NAME")
    full = [str(HOTSPOT)] + cmd
    if dangerous:
        if not args.apply:
            print(f"Dry run natural-language route: {text!r} -> {' '.join(full)}")
            print(f"Impactful command requires --apply --confirm {expected}")
            return
        full.append("--apply")
        full += ["--confirm", args.confirm or expected]
    print(f"Route: {text!r} -> {' '.join(full)}", flush=True)
    proc = subprocess.run(full)
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
