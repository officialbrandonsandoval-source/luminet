#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import plistlib
import re
import secrets
import shutil
import signal
import string
import subprocess
import sys
import time
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_DIR / "config" / "hotspot.json"
BACKUP_DIR = PROJECT_DIR / "backups"
LOG_DIR = PROJECT_DIR / "logs"
EVENT_LOG = LOG_DIR / "hotspot-events.jsonl"
SESSION_LOG = LOG_DIR / "sessions.jsonl"
SECURITY_LOG = LOG_DIR / "security-events.jsonl"
KNOWN_DEVICES_PATH = PROJECT_DIR / "config" / "known_devices.json"
NAT_PLIST = Path("/Library/Preferences/SystemConfiguration/com.apple.nat.plist")
PF_ANCHOR_NAME = "com.luminet.hotspot"
PF_ANCHOR_FILE = Path("/etc/pf.anchors/luminet_guest")
PF_BACKUP_DIR = BACKUP_DIR / "pf"
OPEN_SCRIPT = PROJECT_DIR / "applescript" / "open_internet_sharing.applescript"

SMALL_OUI = {
    "1c:1d:d3": "Apple",
    "d6:89:fd": "Apple randomized/local",
    "10:36:aa": "Vendor unknown/router",
}


def now_iso():
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def run(cmd, check=False, sudo=False):
    if sudo:
        sudo_cmd = ["/usr/bin/sudo"]
        if os.environ.get("SUDO_ASKPASS") and not sys.stdin.isatty():
            sudo_cmd.append("-A")
        cmd = sudo_cmd + cmd
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or proc.stdout.strip() or f"command failed: {' '.join(cmd)}")
    return proc


def log_event(event, **data):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"ts": now_iso(), "event": event, **data}
    with EVENT_LOG.open("a") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")


def log_security(event, severity="info", **data):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"ts": now_iso(), "event": event, "severity": severity, **data}
    with SECURITY_LOG.open("a") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")
    log_event("security_" + event, severity=severity, **data)


def ensure_secure_file(path):
    path = Path(path)
    if path.exists():
        try:
            os.chmod(path, 0o600)
        except PermissionError:
            pass


def default_security_config():
    return {
        "paranoid_mode": False,
        "known_devices": {},
        "auto_block_unknown_devices": False,
        "auto_shutdown_on_serious_anomaly": False,
        "alert_on_new_unknown_devices": True,
        "blocked_devices": [],
        "blocked_ips": [],
        "max_unknown_devices": 2,
        "guest_strict_web_only": True,
        "guest_allow_dns": True,
        "guest_allow_dhcp": True,
        "guest_allow_http_https": True,
        "last_security_review": "",
    }


def security_cfg(cfg):
    sec = default_security_config()
    sec.update(cfg.get("security_hardening", {}))
    return sec


def password_strength(password, minimum=24):
    problems = []
    if len(password or "") < minimum:
        problems.append(f"length<{minimum}")
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "-_.!@#$%^&*+=?"]
    if sum(any(c in cls for c in password or "") for cls in classes) < 3:
        problems.append("needs 3+ character classes")
    if password and len(set(password)) < max(8, len(password)//3):
        problems.append("too little character variety")
    return problems


def hash_dashboard_password(password, salt=None, iterations=310000):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def verify_dashboard_password(password, stored_hash):
    try:
        algo, iterations, salt, digest = stored_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        candidate = hash_dashboard_password(password, salt=salt, iterations=int(iterations)).split("$", 3)[3]
        return hmac.compare_digest(candidate, digest)
    except Exception:
        return False


def load_known_devices():
    if KNOWN_DEVICES_PATH.exists():
        try:
            return json.loads(KNOWN_DEVICES_PATH.read_text())
        except Exception:
            return {}
    return {}


def save_known_devices(devices):
    KNOWN_DEVICES_PATH.parent.mkdir(parents=True, exist_ok=True)
    KNOWN_DEVICES_PATH.write_text(json.dumps(devices, indent=2, sort_keys=True) + "\n")
    os.chmod(KNOWN_DEVICES_PATH, 0o600)


def record_known_devices(devices, label="learned"):
    known = load_known_devices()
    added = []
    for d in devices:
        mac = d.get("mac")
        if not mac or d.get("network") != "hotspot":
            continue
        if mac not in known:
            known[mac] = {"first_seen": now_iso(), "label": label, "ip": d.get("ip", ""), "name": d.get("name", ""), "vendor": d.get("vendor", "unknown")}
            added.append(mac)
    if added:
        save_known_devices(known)
        log_security("known_devices_learned", added=added)
    return added


def analyze_device_anomalies(cfg, devices):
    sec = security_cfg(cfg)
    known = load_known_devices()
    hotspot = [d for d in devices if d.get("network") == "hotspot" and d.get("role") != "Hotspot gateway"]
    unknown = [d for d in hotspot if d.get("mac") not in known]
    anomalies = []
    if unknown:
        anomalies.append({"type": "unknown_devices", "severity": "warning", "count": len(unknown), "devices": unknown})
    if len(unknown) > int(sec.get("max_unknown_devices", 2)):
        anomalies.append({"type": "too_many_unknown_devices", "severity": "critical", "count": len(unknown)})
    active_blocked = []
    blocked_macs = set(sec.get("blocked_devices", []))
    blocked_ips = set(sec.get("blocked_ips", []))
    for d in hotspot:
        if d.get("mac") in blocked_macs or d.get("ip") in blocked_ips:
            active_blocked.append(d)
    if active_blocked:
        anomalies.append({"type": "blocked_device_present", "severity": "critical", "devices": active_blocked})
    return anomalies


def maybe_respond_to_anomalies(cfg, anomalies):
    sec = security_cfg(cfg)
    for a in anomalies:
        log_security("anomaly_detected", severity=a.get("severity", "warning"), anomaly=a)
    if not anomalies:
        return []
    actions = []
    if sec.get("auto_block_unknown_devices"):
        changed = False
        for a in anomalies:
            if a.get("type") == "unknown_devices":
                for d in a.get("devices", []):
                    mac, ip = d.get("mac"), d.get("ip")
                    if mac and mac not in sec["blocked_devices"]:
                        sec["blocked_devices"].append(mac); changed = True
                    if ip and ip not in sec["blocked_ips"]:
                        sec["blocked_ips"].append(ip); changed = True
        if changed:
            cfg["security_hardening"] = sec
            save_config(cfg, event="security_auto_block_updated")
            actions.append("unknown devices added to block list")
    if sec.get("auto_shutdown_on_serious_anomaly") and any(a.get("severity") == "critical" for a in anomalies):
        stop_service(apply=True)
        log_security("emergency_shutdown_triggered", severity="critical", anomalies=anomalies)
        actions.append("Internet Sharing stop requested due to critical anomaly")
    return actions


def load_config():
    if not CONFIG_PATH.exists():
        raise SystemExit(f"Missing config: {CONFIG_PATH}")
    return json.loads(CONFIG_PATH.read_text())


def save_config(cfg, event="config_updated"):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".tmp")
    tmp_path.write_text(json.dumps(cfg, indent=2) + "\n")
    os.chmod(tmp_path, 0o600)
    tmp_path.replace(CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o600)
    log_event(event, config_path=str(CONFIG_PATH))


def require_confirm(expected, got):
    if got != expected:
        raise SystemExit(f"Refusing to continue. Re-run with --confirm {expected}")


def active_profile(cfg):
    key = cfg.get("active_network", "main")
    if key not in ("main", "guest"):
        key = "main"
    profile = dict(cfg.get(key, {}))
    profile["name"] = key
    return key, profile


def active_ssid(cfg):
    _, profile = active_profile(cfg)
    return profile.get("ssid", cfg.get("ssid", "Luminet"))


def active_password(cfg):
    _, profile = active_profile(cfg)
    return profile.get("password", cfg.get("password", ""))


def active_subnet(cfg):
    _, profile = active_profile(cfg)
    return profile.get("subnet", cfg.get("subnet", "192.168.77.0/24"))


def profile_summary(cfg, name):
    profile = cfg.get(name, {})
    return {
        "name": name,
        "ssid": profile.get("ssid", "Luminet-Guest" if name == "guest" else "Luminet"),
        "subnet": profile.get("subnet", "192.168.78.0/24" if name == "guest" else "192.168.77.0/24"),
        "gateway": profile.get("gateway_hint", "192.168.78.1" if name == "guest" else "192.168.77.1"),
        "enabled": bool(profile.get("enabled", name == "main")),
    }


def validate_profile_for_switch(cfg, name):
    profile = cfg.get(name)
    if not isinstance(profile, dict):
        raise SystemExit(f"Cannot switch to {name}: missing '{name}' profile in config/hotspot.json.")
    missing = [key for key in ("ssid", "subnet", "gateway_hint") if not profile.get(key)]
    if missing:
        raise SystemExit(f"Cannot switch to {name}: missing required profile fields: {', '.join(missing)}.")


def live_broadcast_summary(cfg, nat=None):
    nat = nat if nat is not None else read_nat_plist()
    sharing = internet_sharing_state(cfg, nat=nat)
    configured = active_ssid(cfg)
    nat_ssid = sharing.get("ssid") or nat.get("AirPort", {}).get("NetworkName", "") or "unknown"
    bridge = sharing.get("bridge", {})
    if sharing.get("active"):
        if nat_ssid == configured:
            verdict = f"broadcasting configured {cfg.get('active_network', 'main')} profile"
        else:
            verdict = "broadcasting does not match staged profile"
    else:
        verdict = "not broadcasting / not detected"
    return sharing, {
        "configured_ssid": configured,
        "broadcast_ssid": nat_ssid,
        "verdict": verdict,
        "bridge_ip": bridge.get("ip") or "unknown",
        "bridge_active": bridge.get("active"),
    }


def print_one_ssid_warning():
    print("WARNING: macOS Internet Sharing can broadcast only ONE hotspot SSID at a time on this host.")
    print("Switching profiles stages the target SSID in config/NAT. Existing clients may disconnect until Internet Sharing is restarted or toggled in System Settings.")


def source_interface(cfg):
    if cfg.get("source_mode") == "loopback":
        return cfg.get("loopback", {}).get("interface", "lo0")
    return cfg.get("upstream_interface", "en0")


def source_mode(cfg):
    return cfg.get("source_mode") or "interface"


def discover_interfaces():
    return run(["/usr/sbin/networksetup", "-listallhardwareports"]).stdout


def wifi_device_from_networksetup():
    lines = discover_interfaces().splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "Hardware Port: Wi-Fi":
            for j in range(i + 1, min(i + 5, len(lines))):
                if lines[j].strip().startswith("Device:"):
                    return lines[j].split(":", 1)[1].strip()
    return None


def is_internet_sharing_loaded():
    proc = run(["/bin/launchctl", "print", "system/com.apple.InternetSharing"])
    return proc.returncode == 0, proc.stdout + proc.stderr


def nat_primary_device(nat):
    primary = nat.get("NAT", {}).get("PrimaryInterface")
    if isinstance(primary, dict):
        return primary.get("Device", "")
    return primary or ""


def nat_sharing_devices(nat):
    devices = nat.get("NAT", {}).get("SharingDevices", [])
    return devices if isinstance(devices, list) else []


def bridge_status(name="bridge100"):
    proc = run(["/sbin/ifconfig", name])
    text = proc.stdout + proc.stderr
    if proc.returncode != 0:
        return {"name": name, "exists": False, "active": False, "ip": "", "members": [], "text": text}
    ip_match = re.search(r"\binet\s+([0-9.]+)\s+netmask", text)
    members = re.findall(r"\bmember:\s+(\S+)", text)
    return {
        "name": name,
        "exists": True,
        "active": "status: active" in text,
        "ip": ip_match.group(1) if ip_match else "",
        "members": members,
        "text": text,
    }


def internet_sharing_state(cfg, nat=None):
    nat = nat if nat is not None else read_nat_plist()
    launch_loaded, launch_text = is_internet_sharing_loaded()
    bridge = bridge_status("bridge100")
    wifi = cfg.get("wifi_interface", "en1")
    upstream = cfg.get("upstream_interface", "en0")
    ssid = active_ssid(cfg)
    nat_enabled = nat.get("NAT", {}).get("Enabled") == 1
    nat_airport_enabled = nat.get("AirPort", {}).get("Enabled") == 1
    nat_ssid = nat.get("AirPort", {}).get("NetworkName", "")
    primary = nat_primary_device(nat)
    sharing_devices = nat_sharing_devices(nat)
    bridge_ap = any(m.startswith("ap") for m in bridge.get("members", []))
    leases = [d for d in parse_devices(include_arp=False) if d.get("source") == "dhcp"]
    evidence = []
    if launch_loaded:
        evidence.append("launchctl reports com.apple.InternetSharing loaded")
    if nat_enabled and wifi in sharing_devices:
        evidence.append(f"NAT plist enabled and sharing to {wifi}")
    if primary == upstream:
        evidence.append(f"NAT primary interface is {upstream}")
    if nat_airport_enabled and nat_ssid == ssid:
        evidence.append(f"NAT AirPort SSID is {ssid}")
    if bridge.get("active") and bridge.get("ip") and bridge_ap:
        evidence.append(f"{bridge['name']} active at {bridge['ip']} with AP member(s): {', '.join(bridge['members'])}")
    if leases:
        evidence.append(f"DHCP lease(s) present: {len(leases)}")
    active = bool((launch_loaded or (bridge.get("active") and bridge_ap)) and nat_enabled and wifi in sharing_devices)
    if not active and bridge.get("active") and bridge_ap and leases:
        active = True
    return {
        "active": active,
        "launch_loaded": launch_loaded,
        "launch_text": launch_text,
        "bridge": bridge,
        "nat_enabled": nat_enabled,
        "primary": primary,
        "sharing_devices": sharing_devices,
        "ssid": nat_ssid,
        "leases": leases,
        "evidence": evidence,
    }


def read_nat_plist():
    if not NAT_PLIST.exists():
        return {}
    try:
        with NAT_PLIST.open("rb") as f:
            return plistlib.load(f)
    except Exception:
        return {"_error": "could not parse nat plist"}


def backup_nat_plist():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = BACKUP_DIR / f"com.apple.nat.plist.{stamp}.bak"
    if NAT_PLIST.exists():
        shutil.copy2(NAT_PLIST, dest)
        return dest
    return None


def loopback_status(cfg):
    lo = cfg.get("loopback", {})
    iface = lo.get("interface", "lo0")
    ip = lo.get("ip", "192.168.42.1")
    proc = run(["/sbin/ifconfig", iface])
    return ip in proc.stdout, proc.stdout


def ensure_loopback_alias(cfg, apply=False):
    lo = cfg.get("loopback", {})
    iface = lo.get("interface", "lo0")
    ip = lo.get("ip", "192.168.42.1")
    netmask = lo.get("netmask", "255.255.255.0")
    exists, _ = loopback_status(cfg)
    if exists:
        print(f"Loopback alias already present: {iface} {ip}")
        log_event("loopback_already_present", interface=iface, ip=ip)
        return
    if not apply:
        print(f"DRY RUN: would create loopback alias: sudo ifconfig {iface} alias {ip} netmask {netmask}")
        print("Use setup-loopback --apply --confirm LOOPBACK or configure --apply --confirm CONFIGURE")
        return
    run(["/sbin/ifconfig", iface, "alias", ip, "netmask", netmask], check=True, sudo=True)
    log_event("loopback_alias_created", interface=iface, ip=ip, netmask=netmask)
    print(f"Created loopback alias: {iface} {ip}")


def remove_loopback_alias(cfg, apply=False):
    lo = cfg.get("loopback", {})
    iface = lo.get("interface", "lo0")
    ip = lo.get("ip", "192.168.42.1")
    exists, _ = loopback_status(cfg)
    if not exists:
        print(f"Loopback alias not present: {iface} {ip}")
        return
    if not apply:
        print(f"DRY RUN: would remove loopback alias: sudo ifconfig {iface} -alias {ip}")
        return
    run(["/sbin/ifconfig", iface, "-alias", ip], check=True, sudo=True)
    log_event("loopback_alias_removed", interface=iface, ip=ip)
    print(f"Removed loopback alias: {iface} {ip}")



def firewall_enabled_for_active_profile(cfg):
    return cfg.get("active_network") == "guest" and cfg.get("firewall", {}).get("enabled", True)


def private_blocks_for_firewall(cfg):
    fw = cfg.get("firewall", {})
    blocks = list(fw.get("block_private_ranges", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]))
    guest_subnet = cfg.get("guest", {}).get("subnet", "192.168.78.0/24")
    # Do not block guest clients talking to their own DHCP/gateway subnet.
    return [b for b in blocks if b != guest_subnet]


def build_pf_rules(cfg):
    fw = cfg.get("firewall", {})
    sec = security_cfg(cfg)
    wifi = cfg.get("wifi_interface", "en1")
    guest = cfg.get("guest", {})
    guest_subnet = guest.get("subnet", "192.168.78.0/24")
    guest_gw = guest.get("gateway_hint", "192.168.78.1")
    main_subnet = cfg.get("main", {}).get("subnet", "192.168.77.0/24")
    upstream = cfg.get("upstream_interface", "en0")
    blocks = private_blocks_for_firewall(cfg)
    attacker_ports = fw.get("block_common_attacker_ports", [
        "22", "23", "25", "110", "111", "135", "137:139", "143", "389", "445", "548",
        "5900", "593", "1433", "1521", "2049", "2375:2376", "3000:3001", "3306", "3389",
        "5000", "5432", "5601", "5672", "6379", "7000:9000", "9200", "9300", "11211", "27017"
    ])
    blocked_ips = sec.get("blocked_ips", [])
    lines = [
        "# Luminet HARDENED guest isolation anchor",
        "# Managed by Luminet hotspot firewall",
        "# Policy: guest clients get DHCP + DNS + public web only. No Mac access. No private LAN access.",
        f"guest_net = \"{guest_subnet}\"",
        f"guest_gw = \"{guest_gw}\"",
        f"main_net = \"{main_subnet}\"",
        f"wifi_if = \"{wifi}\"",
        f"upstream_if = \"{upstream}\"",
        "attacker_ports = \"{" + " ".join(attacker_ports) + "}\"",
        "",
        "# Kill any active blocks first. Suspicious devices/IPs are explicitly dropped.",
    ]
    for ip in blocked_ips:
        lines.append(f"block drop quick from {ip} to any")
    lines += [
        "",
        "# Required bootstrapping only: DHCP from guest client to the hotspot gateway.",
    ]
    if sec.get("guest_allow_dhcp", True):
        lines.append("pass quick inet proto udp from $guest_net port 68 to $guest_gw port 67 keep state")
    lines += [
        "",
        "# Block all direct access from guests to the Mac Studio itself after required DHCP.",
        "block drop quick from $guest_net to self",
        "block drop quick from $guest_net to $guest_gw",
        "",
        "# Block guests from the main hotspot subnet and every private/local range.",
        "block drop quick from $guest_net to $main_net",
    ]
    seen_blocks = set()
    if fw.get("block_rfc1918", True):
        for block in blocks:
            if block not in seen_blocks:
                lines.append(f"block drop quick from $guest_net to {block}")
                seen_blocks.add(block)
    for cidr in fw.get("extra_block_cidrs", []):
        if cidr not in seen_blocks:
            lines.append(f"block drop quick from $guest_net to {cidr}")
            seen_blocks.add(cidr)
    for cidr in ["100.64.0.0/10", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"]:
        if cidr not in seen_blocks:
            lines.append(f"block drop quick from $guest_net to {cidr}")
            seen_blocks.add(cidr)
    lines += [
        "",
        "# Block common lateral-movement, admin, database, cache, tunnel, and dev-server ports.",
        "block drop quick inet proto { tcp udp } from $guest_net to any port $attacker_ports",
        "",
        "# Minimal internet policy. DNS is allowed; web is allowed; everything else is dropped in paranoid mode.",
    ]
    if sec.get("guest_allow_dns", True):
        lines += [
            "pass quick inet proto udp from $guest_net to any port 53 keep state",
            "pass quick inet proto tcp from $guest_net to any port 53 flags S/SA keep state",
        ]
    if sec.get("guest_allow_http_https", True):
        lines.append("pass quick inet proto tcp from $guest_net to any port { 80 443 } flags S/SA keep state")
    if sec.get("guest_strict_web_only", True):
        lines.append("block drop quick from $guest_net to any")
    else:
        lines.append("pass quick from $guest_net to any keep state")
    lines.append("")
    return "\n".join(lines)

def backup_pf_anchor():
    PF_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    if PF_ANCHOR_FILE.exists():
        dest = PF_BACKUP_DIR / f"luminet_guest.{stamp}.bak"
        shutil.copy2(PF_ANCHOR_FILE, dest)
        return dest
    return None


def firewall_status():
    proc = run(["/sbin/pfctl", "-s", "info"], sudo=True)
    anchor = run(["/sbin/pfctl", "-a", PF_ANCHOR_NAME, "-sr"], sudo=True)
    print("pf info:")
    print((proc.stdout + proc.stderr).strip() or "No pf info returned.")
    print(f"\nAnchor {PF_ANCHOR_NAME} rules:")
    print((anchor.stdout + anchor.stderr).strip() or "No anchor rules loaded.")


def firewall_plan(cfg):
    print(build_pf_rules(cfg))
    print(f"DRY RUN: no pf rules loaded. Anchor: {PF_ANCHOR_NAME}; file: {PF_ANCHOR_FILE}")
    print("Use firewall apply --apply --confirm FIREWALL to write and load rules.")


def guest_test_dryrun():
    """Full dry-run of switching to guest profile: config diff, NAT plist preview,
    firewall plan, lockdown preview, and rollback plan. Nothing is written."""
    cfg = load_config()
    current = cfg.get("active_network", "main")
    sec = security_cfg(cfg)
    sharing = internet_sharing_state(cfg)
    bridge = sharing.get("bridge", {})

    print("=" * 64)
    print("GUEST MODE DRY-RUN TEST")
    print("=" * 64)
    print(f"Current active profile: {current}")
    print(f"Target active profile:   guest")
    print(f"Internet Sharing active: {sharing['active']}")
    print(f"Bridge: {bridge.get('name', 'bridge100')} active={bridge.get('active')} ip={bridge.get('ip')}")

    # --- 1. Config changes ---
    print("\n--- 1. CONFIG CHANGES (guest enable would write) ---")
    print(f"  active_network: {current} -> guest")
    print(f"  guest.enabled: {cfg.get('guest', {}).get('enabled')} -> True")
    guest_cfg = cfg.get("guest", {})
    print(f"  Guest SSID:            {guest_cfg.get('ssid', 'Luminet-Guest')}")
    print(f"  Guest subnet:          {guest_cfg.get('subnet', '192.168.78.0/24')}")
    print(f"  Guest gateway:         {guest_cfg.get('gateway_hint', '192.168.78.1')}")
    print(f"  Guest password length: {len(guest_cfg.get('password', ''))} chars")
    print(f"  Upstream interface:    {cfg.get('upstream_interface', 'en0')}")
    print(f"  Wi-Fi interface:       {cfg.get('wifi_interface', 'en1')}")

    # --- 2. NAT plist preview ---
    print("\n--- 2. NAT PLIST PREVIEW (configure --apply would write) ---")
    nat_preview = {
        "NAT": {"Enabled": 1, "PrimaryInterface": cfg.get("upstream_interface", "en0"),
                 "PrimaryService": "...", "SharingDevices": [cfg.get("wifi_interface", "en1")]},
        "AirPort": {"Enabled": 1, "NetworkName": guest_cfg.get("ssid", "Luminet-Guest")},
        "SharingNetworkNumberStart": str(guest_cfg.get("subnet", "192.168.78.0/24")).rsplit(".", 1)[0] + ".2",
        "SharingNetworkNumberEnd": str(guest_cfg.get("subnet", "192.168.78.0/24")).rsplit(".", 1)[0] + ".254",
    }
    print(f"  NAT.Enabled:           {nat_preview['NAT']['Enabled']}")
    print(f"  NAT.PrimaryInterface:  {nat_preview['NAT']['PrimaryInterface']}")
    print(f"  NAT.SharingDevices:    {nat_preview['NAT']['SharingDevices']}")
    print(f"  AirPort.NetworkName:   {nat_preview['AirPort']['NetworkName']}")
    print(f"  DHCP range:           {nat_preview['SharingNetworkNumberStart']} - {nat_preview['SharingNetworkNumberEnd']}")

    # --- 3. Firewall plan ---
    print("\n--- 3. FIREWALL PLAN (lockdown enable or firewall apply would load) ---")
    print(f"  pf anchor:              {PF_ANCHOR_NAME}")
    print(f"  pf anchor file:         {PF_ANCHOR_FILE}")
    print(f"  Strict guest isolation: {sec.get('guest_strict_web_only')}")
    print(f"  Allow DHCP:             {sec.get('guest_allow_dhcp')}")
    print(f"  Allow DNS:              {sec.get('guest_allow_dns')}")
    print(f"  Allow HTTP/HTTPS:       {sec.get('guest_allow_http_https')}")
    print(f"  Block RFC1918:          {cfg.get('firewall', {}).get('block_rfc1918')}")
    print(f"  Block attacker ports:  {len(cfg.get('firewall', {}).get('block_common_attacker_ports', []))} ranges")
    print(f"  Blocked IPs:            {len(sec.get('blocked_ips', []))}")
    print(f"  Paranoid default-drop:  {sec.get('paranoid_mode')}")
    print("\n  Full pf rules preview:")
    print("  " + "-" * 50)
    rules = build_pf_rules(cfg)
    for line in rules.splitlines():
        print(f"  {line}")
    print("  " + "-" * 50)

    # --- 4. Lockdown preview ---
    print("\n--- 4. LOCKDOWN PREVIEW (lockdown enable would apply) ---")
    print("  Paranoid Mode:              ON")
    print("  Auto-block unknown devices: ON")
    print("  Auto-shutdown on anomaly:   ON")
    print("  Alert on unknown devices:   ON (already on)")
    print("  macOS services to disable:")
    for svc in LOCKDOWN_SERVICES:
        label = f"{svc['domain']}/{svc['service']}"
        state = _launchctl_service_state(label)
        print(f"    {svc['label']}: {state}")

    # --- 5. Rollback plan ---
    print("\n--- 5. ROLLBACK PLAN (if anything goes wrong) ---")
    print("  1. ./bin/hotspot lockdown disable     # restore services + paranoid off")
    print("  2. ./bin/emergency-network-reset --apply --confirm RESET")
    print("     (stops sharing, flushes pf, cleans loopback, restores lockdown,")
    print("      removes NAT plist matching Luminet)")
    print("  3. Manual: System Settings > General > Sharing > Internet Sharing OFF")
    print("")
    print("  Or combined single rollback:")
    print("    ./bin/emergency-network-reset --apply --confirm RESET")
    print("    (this now includes lockdown disable automatically)")

    # --- 6. Pre-flight checks ---
    print("\n--- 6. PRE-FLIGHT CHECKS ---")
    checks = [
        (len(cfg.get("main", {}).get("password", "")) >= 24, f"Main password >= 24 chars ({len(cfg.get('main', {}).get('password', ''))} chars)"),
        (len(cfg.get("guest", {}).get("password", "")) >= 24, f"Guest password >= 24 chars ({len(cfg.get('guest', {}).get('password', ''))} chars)"),
        (bool(cfg.get("dashboard", {}).get("password_hash")), "Dashboard password stored as hash"),
        ((CONFIG_PATH.stat().st_mode & 0o077) == 0, "Config file permissions 0600"),
        (sec.get("guest_strict_web_only"), "Guest strict web-only enabled"),
        (sec.get("guest_allow_dns"), "Guest DNS allowed"),
        (sec.get("guest_allow_dhcp"), "Guest DHCP allowed"),
        (sec.get("alert_on_new_unknown_devices"), "Alert on unknown devices"),
        (len(load_known_devices()) >= 1, f"Known devices learned ({len(load_known_devices())})"),
    ]
    all_ok = True
    for ok, label in checks:
        marker = "OK" if ok else "!!"
        if not ok:
            all_ok = False
        print(f"  [{marker}] {label}")

    print("\n" + "=" * 64)
    if all_ok:
        print("ALL PRE-FLIGHT CHECKS PASSED. Ready for live test.")
    else:
        print("SOME CHECKS FAILED. Review before proceeding.")
    print("=" * 64)
    print("\nSHORTEST LIVE TEST SEQUENCE:")
    print("  1. ./bin/hotspot guest enable")
    print("  2. ./bin/hotspot configure --apply --confirm CONFIGURE")
    print("  3. ./bin/hotspot lockdown enable")
    print("  4. ./bin/hotspot start --apply --confirm ENABLE")
    print("     (if start fails -> ./bin/hotspot open-settings)")
    print("  5. Connect device to Luminet-Guest, verify isolation")
    print("")
    print("ROLLBACK:")
    print("  ./bin/emergency-network-reset --apply --confirm RESET")


def firewall_apply(cfg, apply=False):
    rules = build_pf_rules(cfg)
    if not apply:
        firewall_plan(cfg)
        return
    backup = backup_pf_anchor()
    tmp = Path("/tmp/luminet_guest.pf")
    tmp.write_text(rules + "\n")
    run(["/bin/mkdir", "-p", str(PF_ANCHOR_FILE.parent)], check=True, sudo=True)
    run(["/bin/cp", str(tmp), str(PF_ANCHOR_FILE)], check=True, sudo=True)
    run(["/usr/sbin/chown", "root:wheel", str(PF_ANCHOR_FILE)], check=True, sudo=True)
    run(["/bin/chmod", "644", str(PF_ANCHOR_FILE)], check=True, sudo=True)
    check = run(["/sbin/pfctl", "-nf", str(PF_ANCHOR_FILE)], sudo=True)
    if check.returncode != 0:
        raise SystemExit(check.stderr.strip() or check.stdout.strip() or "pf syntax check failed")
    load = run(["/sbin/pfctl", "-a", PF_ANCHOR_NAME, "-f", str(PF_ANCHOR_FILE)], sudo=True)
    if load.returncode != 0:
        raise SystemExit(load.stderr.strip() or load.stdout.strip() or "pf anchor load failed")
    enable = run(["/sbin/pfctl", "-E"], sudo=True)
    log_event("firewall_rules_loaded", anchor=PF_ANCHOR_NAME, anchor_file=str(PF_ANCHOR_FILE), backup=str(backup) if backup else None)
    print(f"Loaded pf guest isolation rules into anchor {PF_ANCHOR_NAME}")
    if backup:
        print(f"Backup: {backup}")
    if enable.stderr.strip():
        print(enable.stderr.strip())


def firewall_remove(apply=False):
    if not apply:
        print(f"DRY RUN: would flush pf anchor {PF_ANCHOR_NAME}")
        print("Use firewall remove --apply --confirm FIREWALL_REMOVE")
        return
    proc = run(["/sbin/pfctl", "-a", PF_ANCHOR_NAME, "-F", "rules"], sudo=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or proc.stdout.strip() or "pf anchor flush failed")
    log_event("firewall_rules_removed", anchor=PF_ANCHOR_NAME)
    print(f"Flushed pf anchor {PF_ANCHOR_NAME}")

def build_nat_plist(cfg):
    network = ipaddress.ip_network(active_subnet(cfg), strict=False)
    hosts = list(network.hosts())
    return {
        "NAT": {
            "Enabled": 1,
            "PrimaryInterface": source_interface(cfg),
            "SharingDevices": [cfg["wifi_interface"]],
        },
        "SharingNetworkNumberStart": str(hosts[1] if len(hosts) > 1 else hosts[0]),
        "SharingNetworkNumberEnd": str(hosts[-1]),
        "AirPort": {
            "Enabled": 1,
            "NetworkName": active_ssid(cfg),
            "Channel": 0,
        },
    }


def write_nat_plist(cfg, apply=False):
    planned = build_nat_plist(cfg)
    if not apply:
        print(json.dumps(planned, indent=2))
        print("DRY RUN: no plist written. Use configure --apply --confirm CONFIGURE")
        return
    if cfg.get("source_mode") == "loopback":
        ensure_loopback_alias(cfg, apply=True)
    backup = backup_nat_plist()
    tmp = Path("/tmp/luminet-com.apple.nat.plist")
    with tmp.open("wb") as f:
        plistlib.dump(planned, f)
    run(["/bin/mkdir", "-p", str(NAT_PLIST.parent)], check=True, sudo=True)
    run(["/bin/cp", str(tmp), str(NAT_PLIST)], check=True, sudo=True)
    run(["/usr/sbin/chown", "root:wheel", str(NAT_PLIST)], check=True, sudo=True)
    run(["/bin/chmod", "644", str(NAT_PLIST)], check=True, sudo=True)
    log_event("nat_config_written", nat_plist=str(NAT_PLIST), backup=str(backup) if backup else None, ssid=active_ssid(cfg), source=source_interface(cfg), subnet=active_subnet(cfg))
    print(f"Wrote {NAT_PLIST}")
    if backup:
        print(f"Backup: {backup}")


def start_service(apply=False):
    if not apply:
        print("DRY RUN: would start com.apple.InternetSharing via launchctl.")
        print("Use start --apply --confirm ENABLE")
        return
    session = {"ts": now_iso(), "action": "start", "ssid": active_ssid(load_config())}
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with SESSION_LOG.open("a") as f:
        f.write(json.dumps(session, sort_keys=True) + "\n")
    run(["/bin/launchctl", "bootout", "system/com.apple.InternetSharing"], sudo=True)
    proc = run(["/bin/launchctl", "bootstrap", "system", "/System/Library/LaunchDaemons/com.apple.InternetSharing.plist"], sudo=True)
    if proc.returncode != 0:
        proc2 = run(["/bin/launchctl", "kickstart", "-k", "system/com.apple.InternetSharing"], sudo=True)
        if proc2.returncode != 0:
            log_event("hotspot_start_failed", error=(proc.stderr + proc2.stderr).strip())
            raise SystemExit((proc.stderr + proc2.stderr).strip())
    log_event("hotspot_start_requested")
    print("Requested Internet Sharing start.")


def stop_service(apply=False):
    if not apply:
        print("DRY RUN: would stop com.apple.InternetSharing via launchctl.")
        print("Use stop --apply --confirm DISABLE")
        return
    proc = run(["/bin/launchctl", "bootout", "system/com.apple.InternetSharing"], sudo=True)
    if proc.returncode != 0:
        msg = proc.stderr.strip() or "Internet Sharing was not loaded."
        print(msg)
        log_event("hotspot_stop_noop", message=msg)
    else:
        log_event("hotspot_stop_requested")
        print("Requested Internet Sharing stop.")


def generate_password(length=32):
    alphabet = string.ascii_letters + string.digits + "-_.!@#$%^&*+=?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def parse_devices(include_arp=True):
    devices = {}
    for p in [Path("/var/db/dhcpd_leases"), Path("/private/var/db/dhcpd_leases")]:
        if p.exists():
            text = p.read_text(errors="ignore")
            blocks = re.split(r"\n\s*\n", text)
            for b in blocks:
                ip = re.search(r"ip_address=([^\n;]+)", b) or re.search(r"ip_address\s*=\s*([^;\n]+)", b)
                mac = re.search(r"hw_address=1,([^\n;]+)", b) or re.search(r"hardware ethernet\s+([^;\n]+)", b)
                name = re.search(r"name=([^\n;]+)", b) or re.search(r"hostname=([^\n;]+)", b) or re.search(r"client-hostname\s+\"([^\"]+)\"", b)
                if mac:
                    m = mac.group(1).strip().lower()
                    devices[m] = {"mac": m, "ip": ip.group(1).strip() if ip else "", "name": name.group(1).strip().strip('"') if name else "", "source": "dhcp"}
            break
    if include_arp:
        arp = run(["/usr/sbin/arp", "-an"]).stdout
        for line in arp.splitlines():
            m = re.search(r"\(([^)]+)\) at ([0-9a-f:]{11,17}|incomplete)", line, re.I)
            if not m or m.group(2).lower() == "incomplete":
                continue
            ip, mac = m.group(1), m.group(2).lower()
            devices.setdefault(mac, {"mac": mac, "ip": ip, "name": "", "source": "arp"})
            if not devices[mac].get("ip"):
                devices[mac]["ip"] = ip
    bridge = bridge_status("bridge100")
    bridge_ip = bridge.get("ip", "")
    bridge_prefix = ".".join(bridge_ip.split(".")[:3]) + "." if bridge_ip.count(".") == 3 else ""
    for d in devices.values():
        prefix = ":".join(d["mac"].split(":")[:3])
        d["vendor"] = SMALL_OUI.get(prefix, "unknown")
        d["network"] = "hotspot" if d.get("source") == "dhcp" or (bridge_prefix and d.get("ip", "").startswith(bridge_prefix)) else "other-lan"
        if d.get("ip") == bridge_ip:
            d["role"] = "Hotspot gateway"
        else:
            d["role"] = "Hotspot client" if d["network"] == "hotspot" else "Other LAN/ARP"
    return sorted(devices.values(), key=lambda x: (x.get("network") != "hotspot", x.get("ip") or "", x["mac"]))


def connected_devices(json_out=False):
    devices = parse_devices()
    if json_out:
        print(json.dumps(devices, indent=2))
        return
    if not devices:
        print("No devices found in DHCP leases or ARP table.")
        return
    print(f"{'Role':<16} {'IP':<18} {'Name':<18} {'MAC':<20} {'Vendor':<24} Source")
    print("-" * 112)
    for d in devices:
        print(f"{d.get('role',''):<16} {d.get('ip',''):<18} {d.get('name',''):<18} {d['mac']:<20} {d.get('vendor','unknown'):<24} {d.get('source','')}")


def notify(title, message):
    run(["/usr/bin/osascript", "-e", f'display notification "{message}" with title "{title}"'])


def monitor(interval=None, notify_new=False, once=False):
    cfg = load_config()
    interval = interval or int(cfg.get("monitoring", {}).get("interval_seconds", 5))
    seen = {d["mac"]: d for d in parse_devices()}
    print(f"Monitoring devices every {interval}s. Ctrl-C to stop.")
    log_event("monitor_started", interval=interval)
    try:
        while True:
            cfg = load_config()
            current_devices = parse_devices()
            current = {d["mac"]: d for d in current_devices}
            joined = [d for mac, d in current.items() if mac not in seen]
            left = [d for mac, d in seen.items() if mac not in current]
            for d in joined:
                log_event("device_joined", **d)
                print(f"JOIN {d.get('ip','')} {d['mac']} {d.get('vendor','unknown')} {d.get('name','')}")
                if d.get("network") == "hotspot" and d.get("mac") not in load_known_devices():
                    log_security("unknown_device_joined", severity="warning", device=d)
                    if cfg.get("notifications", {}).get("enabled") or notify_new:
                        notify("Luminet", f"Unknown device joined: {d['mac']} {d.get('ip','')}")
                elif notify_new or cfg.get("notifications", {}).get("enabled"):
                    notify("Luminet", f"Device joined: {d['mac']} {d.get('ip','')}")
            for d in left:
                log_event("device_left", **d)
                print(f"LEFT {d.get('ip','')} {d['mac']} {d.get('vendor','unknown')} {d.get('name','')}")
            anomalies = analyze_device_anomalies(cfg, current_devices)
            actions = maybe_respond_to_anomalies(cfg, anomalies)
            for a in anomalies:
                print(f"ANOMALY {a.get('severity','warning').upper()} {a.get('type')} count={a.get('count','')}")
            for action in actions:
                print(f"RESPONSE {action}")
            seen = current
            if once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        log_event("monitor_stopped")
        print("Monitor stopped.")


def learn_current_devices():
    devices = parse_devices()
    added = record_known_devices(devices)
    print(f"Learned {len(added)} hotspot device(s) into {KNOWN_DEVICES_PATH}")
    if added:
        for mac in added:
            print(f"  - {mac}")


def show_logs(recent=False, limit=40):
    if not EVENT_LOG.exists():
        print("No hotspot event log yet.")
        return
    lines = EVENT_LOG.read_text().splitlines()
    if recent:
        lines = lines[-limit:]
    for line in lines:
        print(line)



def rotate_password(profile, length=32, show=False):
    if length < 24:
        raise SystemExit("Refusing weak rotation. Use length >= 24.")
    cfg = load_config()
    pw = generate_password(length)
    if profile in ("main", "guest"):
        cfg.setdefault(profile, {})["password"] = pw
        event = f"{profile}_password_rotated"
    elif profile == "dashboard":
        cfg.setdefault("dashboard", {})["password_hash"] = hash_dashboard_password(pw)
        cfg["dashboard"].pop("password", None)
        event = "dashboard_password_rotated_hashed"
    else:
        raise SystemExit("profile must be main, guest, or dashboard")
    save_config(cfg, event=event)
    print(f"Rotated {profile} password. Config saved chmod 600.")
    if show:
        print(pw)
    else:
        print("Password hidden. Re-run status --show-secret only when needed, or rotate with --show once in a private terminal.")


def enable_paranoid_mode(apply=False):
    cfg = load_config()
    sec = security_cfg(cfg)
    sec.update({
        "paranoid_mode": True,
        "auto_block_unknown_devices": True,
        "auto_shutdown_on_serious_anomaly": True,
        "alert_on_new_unknown_devices": True,
        "guest_strict_web_only": True,
        "guest_allow_dns": True,
        "guest_allow_dhcp": True,
        "guest_allow_http_https": True,
        "last_security_review": now_iso(),
    })
    cfg["security_hardening"] = sec
    dash = cfg.setdefault("dashboard", {})
    dash.setdefault("rate_limit", {"window_seconds": 60, "max_requests": 90, "max_failed_logins": 5, "lockout_seconds": 300})
    dash.setdefault("session_timeout_seconds", 300)
    dash.setdefault("https", {"enabled": False, "cert_file": str(PROJECT_DIR / "certs" / "dashboard.crt"), "key_file": str(PROJECT_DIR / "certs" / "dashboard.key")})
    save_config(cfg, event="paranoid_mode_enabled")
    print("Paranoid Mode enabled in config.")
    print("It does not switch to Guest Mode or apply pf until you explicitly run firewall/start commands.")
    if apply:
        firewall_apply(cfg, apply=True)


def disable_paranoid_mode():
    cfg = load_config()
    sec = security_cfg(cfg)
    sec["paranoid_mode"] = False
    sec["auto_block_unknown_devices"] = False
    sec["auto_shutdown_on_serious_anomaly"] = False
    cfg["security_hardening"] = sec
    save_config(cfg, event="paranoid_mode_disabled")
    print("Paranoid Mode disabled in config. Existing firewall rules are not removed automatically.")


def generate_dashboard_cert():
    cfg = load_config()
    https = cfg.setdefault("dashboard", {}).setdefault("https", {})
    cert = Path(https.get("cert_file") or PROJECT_DIR / "certs" / "dashboard.crt")
    key = Path(https.get("key_file") or PROJECT_DIR / "certs" / "dashboard.key")
    cert.parent.mkdir(parents=True, exist_ok=True)
    subj = "/CN=Luminet Dashboard"
    proc = run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "825", "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", subj, "-addext", "subjectAltName=IP:192.168.2.1,IP:127.0.0.1,DNS:localhost"], check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or proc.stdout.strip() or "openssl certificate generation failed")
    os.chmod(key, 0o600); os.chmod(cert, 0o644)
    https.update({"enabled": True, "cert_file": str(cert), "key_file": str(key)})
    cfg["dashboard"]["https"] = https
    save_config(cfg, event="dashboard_https_cert_generated")
    print(f"Generated self-signed dashboard certificate: {cert}")
    print(f"Private key: {key} (chmod 600)")


# ---------------------------------------------------------------------------
# Lockdown Mode
# ---------------------------------------------------------------------------
# Lockdown = Paranoid Mode PLUS disabling unnecessary macOS surface-area
# services (AirDrop, Bluetooth Sharing, Remote Login, Screen Sharing,
# Apache, etc.) while the hotspot is active.
# Unlock reverses every change.

LOCKDOWN_STATE_FILE = PROJECT_DIR / "config" / "lockdown_state.json"

# Services we touch during lockdown.  Each entry maps a friendly label to
# the launchd domain/service path used by macOS.  We only toggle services
# that are safe to disable on a headless Mac Studio serving a hotspot.
LOCKDOWN_SERVICES = [
    {"label": "AirDrop (Bluetooth Sharing)", "domain": "system", "service": "com.apple.sharing"},
    {"label": "Remote Login (SSH)", "domain": "system", "service": "com.apple.sshd"},
    {"label": "Screen Sharing (VNC)", "domain": "gui", "service": "com.apple.screensharing"},
    {"label": "Apache httpd", "domain": "system", "service": "org.apache.httpd"},
    {"label": "CUPS printing", "domain": "system", "service": "org.cups.cupsd"},
    {"label": "Bluetooth Sharing agent", "domain": "gui", "service": "com.apple.BluetoothSharingAgent"},
]

LOCKDOWN_LAUNCHCTL_DISABLE_LABELS = [
    "system/com.apple.sharing",
    "system/com.apple.sshd",
    "gui/com.apple.screensharing",
    "system/org.apache.httpd",
    "system/org.cups.cupsd",
]


def _launchctl_service_state(label):
    """Return 'enabled'/'disabled'/unknown for a launchd service label."""
    proc = run(["/bin/launchctl", "print", label], sudo=False)
    # If print succeeds, service is loaded/enabled
    if proc.returncode == 0:
        return "enabled"
    out = (proc.stdout + proc.stderr).lower()
    if "could not find" in out or "not found" in out:
        return "disabled"
    return "unknown"


def enable_lockdown(apply_firewall=True):
    """Lockdown Mode: Paranoid Mode + strictest firewall + disarm macOS services."""
    cfg = load_config()

    # --- 1. Enable paranoid mode in config ---
    sec = security_cfg(cfg)
    sec.update({
        "paranoid_mode": True,
        "auto_block_unknown_devices": True,
        "auto_shutdown_on_serious_anomaly": True,
        "alert_on_new_unknown_devices": True,
        "guest_strict_web_only": True,
        "guest_allow_dns": True,
        "guest_allow_dhcp": True,
        "guest_allow_http_https": True,
        "last_security_review": now_iso(),
    })
    cfg["security_hardening"] = sec
    save_config(cfg, event="lockdown_mode_enabling")

    # --- 2. Snapshot current state of every service we're about to touch ---
    snapshot = []
    disabled_services = []
    for svc in LOCKDOWN_SERVICES:
        label = f"{svc['domain']}/{svc['service']}"
        state = _launchctl_service_state(label)
        snapshot.append({"label": label, "label_friendly": svc["label"], "state": state})

    # --- 3. Disable services (launchctl disable) ---
    for label in LOCKDOWN_LAUNCHCTL_DISABLE_LABELS:
        proc = run(["/bin/launchctl", "disable", label], sudo=True)
        status = "disabled" if proc.returncode == 0 else f"failed (rc={proc.returncode})"
        # Re-check state
        new_state = _launchctl_service_state(label)
        disabled_services.append({"label": label, "action": "disable", "result": status, "after": new_state})

    # --- 4. Save state snapshot for later unlock ---
    LOCKDOWN_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state_payload = {
        "locked_at": now_iso(),
        "snapshot": snapshot,
        "disabled_services": disabled_services,
    }
    LOCKDOWN_STATE_FILE.write_text(json.dumps(state_payload, indent=2))
    os.chmod(LOCKDOWN_STATE_FILE, 0o600)
    log_security("lockdown_enabled", severity="critical", disabled=[s["label"] for s in disabled_services])

    # --- 5. Apply firewall if requested ---
    if apply_firewall:
        firewall_apply(cfg, apply=True)
    else:
        print("Lockdown Mode: Paranoid config saved. Firewall NOT applied (use --apply-firewall or run firewall apply separately).")

    print("\n" + "=" * 60)
    print("LOCKDOWN MODE ENABLED")
    print("=" * 60)
    print("Paranoid Mode:              ON")
    print("Auto-block unknown devices: ON")
    print("Auto-shutdown on anomaly:   ON")
    print("Alert on unknown devices:   ON")
    print("Guest strict web-only:      ON")
    print("macOS services disabled:")
    for s in disabled_services:
        marker = "OK" if "disabled" in s.get("result", "") else "!!"
        print(f"  [{marker}] {s['label']}")
    if apply_firewall:
        print("pf guest isolation:         APPLIED")
    print("=" * 60)
    print(f"Lockdown state saved: {LOCKDOWN_STATE_FILE}")
    print("Use: ./bin/hotspot lockdown disable   to restore all services.")


def disable_lockdown():
    """Reverse Lockdown Mode: re-enable paranoid-off + restore macOS services."""
    cfg = load_config()

    # --- 1. Disable paranoid mode ---
    sec = security_cfg(cfg)
    sec.update({
        "paranoid_mode": False,
        "auto_block_unknown_devices": False,
        "auto_shutdown_on_serious_anomaly": False,
        "last_security_review": now_iso(),
    })
    cfg["security_hardening"] = sec
    save_config(cfg, event="lockdown_mode_disabling")

    # --- 2. Restore services from saved state ---
    restored = []
    if LOCKDOWN_STATE_FILE.exists():
        state = json.loads(LOCKDOWN_STATE_FILE.read_text())
        # Re-enable each launchd service we disabled
        for label in LOCKDOWN_LAUNCHCTL_DISABLE_LABELS:
            proc = run(["/bin/launchctl", "enable", label], sudo=True)
            status = "enabled" if proc.returncode == 0 else f"failed (rc={proc.returncode})"
            restored.append({"label": label, "action": "enable", "result": status})
        # Clean up state file
        LOCKDOWN_STATE_FILE.unlink(missing_ok=True)
    else:
        # No state file -- re-enable everything anyway
        for label in LOCKDOWN_LAUNCHCTL_DISABLE_LABELS:
            proc = run(["/bin/launchctl", "enable", label], sudo=True)
            status = "enabled" if proc.returncode == 0 else f"failed (rc={proc.returncode})"
            restored.append({"label": label, "action": "enable", "result": status})

    log_security("lockdown_disabled", severity="info", restored=[s["label"] for s in restored])

    # --- 3. Offer to remove firewall ---
    print("\n" + "=" * 60)
    print("LOCKDOWN MODE DISABLED")
    print("=" * 60)
    print("Paranoid Mode:              OFF")
    print("Auto-block unknown devices: OFF")
    print("Auto-shutdown on anomaly:   OFF")
    print("macOS services re-enabled:")
    for s in restored:
        marker = "OK" if "enabled" in s.get("result", "") else "!!"
        print(f"  [{marker}] {s['label']}")
    print("=" * 60)
    print("pf guest isolation rules are NOT removed automatically.")
    print("To remove them:  ./bin/hotspot firewall remove --apply --confirm FIREWALL_REMOVE")


def lockdown_status():
    """Show current lockdown/paranoid state and service status."""
    cfg = load_config()
    sec = security_cfg(cfg)

    print("Lockdown / Paranoid Status")
    print("=" * 40)
    print(f"Paranoid Mode:              {sec.get('paranoid_mode', False)}")
    print(f"Auto-block unknown devices: {sec.get('auto_block_unknown_devices', False)}")
    print(f"Auto-shutdown on anomaly:   {sec.get('auto_shutdown_on_serious_anomaly', False)}")
    print(f"Alert on unknown devices:   {sec.get('alert_on_new_unknown_devices', True)}")
    print(f"Guest strict web-only:     {sec.get('guest_strict_web_only', True)}")

    # Load saved state if it exists
    locked = False
    if LOCKDOWN_STATE_FILE.exists():
        state = json.loads(LOCKDOWN_STATE_FILE.read_text())
        locked = True
        print(f"\nLockdown state file:        {LOCKDOWN_STATE_FILE}")
        print(f"  Locked at: {state.get('locked_at', 'unknown')}")
        print("  Services at lock time:")
        for s in state.get("snapshot", []):
            print(f"    {s['label_friendly']}: {s['state']}")
    else:
        print("\nNo lockdown state file found (lockdown has never been enabled, or was disabled).")

    # Current service state
    print("\nCurrent macOS service states:")
    for svc in LOCKDOWN_SERVICES:
        label = f"{svc['domain']}/{svc['service']}"
        state = _launchctl_service_state(label)
        print(f"  {svc['label']}: {state}")

    if locked:
        print("\n*** LOCKDOWN IS ACTIVE ***")
    elif sec.get("paranoid_mode"):
        print("\nParanoid Mode is on (config-only, services NOT locked down).")


def security_status():
    cfg = load_config()
    sec = security_cfg(cfg)
    dash = cfg.get("dashboard", {})
    devices = parse_devices()
    anomalies = analyze_device_anomalies(cfg, devices)
    print("Luminet Security Status")
    print("===========================")
    print(f"Paranoid Mode: {sec.get('paranoid_mode')}")
    print(f"Guest strict web-only: {sec.get('guest_strict_web_only')}")
    print(f"Auto-block unknown devices: {sec.get('auto_block_unknown_devices')}")
    print(f"Auto-shutdown on serious anomaly: {sec.get('auto_shutdown_on_serious_anomaly')}")
    print(f"Known devices file: {KNOWN_DEVICES_PATH} ({len(load_known_devices())} known)")
    print(f"Blocked MACs: {len(sec.get('blocked_devices', []))}")
    print(f"Blocked IPs: {len(sec.get('blocked_ips', []))}")
    print(f"Dashboard session timeout: {dash.get('session_timeout_seconds', 300)} seconds")
    print(f"Dashboard password storage: {'PBKDF2 hash' if dash.get('password_hash') else 'plaintext legacy password'}")
    print(f"Dashboard HTTPS: {dash.get('https', {}).get('enabled', False)}")
    print(f"Config permissions: {oct(CONFIG_PATH.stat().st_mode & 0o777)}")
    print("\nPassword checks:")
    for prof in ("main", "guest"):
        pw = cfg.get(prof, {}).get("password", "")
        problems = password_strength(pw)
        print(f"  {prof}: {'OK' if not problems else 'WEAK ' + ', '.join(problems)}")
    if dash.get("password"):
        problems = password_strength(dash.get("password", ""))
        print(f"  dashboard: {'OK but plaintext legacy' if not problems else 'WEAK ' + ', '.join(problems)}")
    elif dash.get("password_hash"):
        print("  dashboard: hash stored; plaintext not recoverable")
    print("\nCurrent anomalies:")
    if not anomalies:
        print("  none detected")
    else:
        for a in anomalies:
            print(f"  - {a.get('severity','warning').upper()}: {a.get('type')} count={a.get('count','')}")
    print("\nChecklist:")
    checklist = [
        (sec.get("paranoid_mode"), "Paranoid Mode enabled"),
        (sec.get("guest_strict_web_only"), "Guest restricted to DHCP/DNS/HTTP/HTTPS only"),
        (dash.get("session_timeout_seconds", 0) <= 300, "Dashboard auto-logout <= 5 minutes"),
        (bool(dash.get("rate_limit")), "Dashboard rate limiting configured"),
        (bool(dash.get("password_hash")), "Dashboard password stored as PBKDF2 hash"),
        ((CONFIG_PATH.stat().st_mode & 0o077) == 0, "Config not group/world readable"),
    ]
    for ok, label in checklist:
        print(f"  [{'OK' if ok else '!!'}] {label}")

def switch_profile(target):
    if target not in ("main", "guest"):
        raise SystemExit("Target must be main or guest.")
    cfg = load_config()
    validate_profile_for_switch(cfg, target)
    previous = cfg.get("active_network", "main")
    if previous not in ("main", "guest"):
        print(f"WARNING: active_network was invalid ({previous!r}); treating previous profile as main.")
        previous = "main"
    prev_profile = profile_summary(cfg, previous)
    target_profile = profile_summary(cfg, target)
    cfg["active_network"] = target
    cfg.setdefault("guest", {})["enabled"] = target == "guest"
    save_config(cfg, event=f"profile_switch_{previous}_to_{target}")
    print("Profile switch staged.")
    print(f"Previous profile: {previous} ({prev_profile['ssid']})")
    print(f"New active profile: {target} ({target_profile['ssid']})")
    print(f"Target subnet: {target_profile['subnet']}")
    print_one_ssid_warning()
    print("")
    print("This changed project config only. To apply it to macOS Internet Sharing:")
    print('  1. SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/hotspot configure --apply --confirm CONFIGURE')
    if target == "guest":
        print('  2. SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/hotspot firewall apply --apply --confirm FIREWALL')
        print('  3. SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/hotspot start --apply --confirm ENABLE')
    else:
        print('  2. Optional: SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/hotspot firewall remove --apply --confirm FIREWALL_REMOVE')
        print('  3. SUDO_ASKPASS="$PWD/bin/sudo-askpass" ./bin/hotspot start --apply --confirm ENABLE')
    print("If launchctl fails, run: ./bin/hotspot open-settings and toggle Internet Sharing manually.")


def status(show_secret=False):
    cfg = load_config()
    wifi = wifi_device_from_networksetup()
    nat = read_nat_plist()
    sharing, broadcast = live_broadcast_summary(cfg, nat=nat)
    loaded = sharing["active"]
    launch_text = sharing["launch_text"]
    loop_ok, _ = loopback_status(cfg)
    safe_cfg = json.loads(json.dumps(cfg))
    if not show_secret:
        for key in ("main", "guest"):
            if key in safe_cfg and "password" in safe_cfg[key]:
                safe_cfg[key]["password"] = "***"
        if "dashboard" in safe_cfg and "password" in safe_cfg["dashboard"]:
            safe_cfg["dashboard"]["password"] = "***"
        if "dashboard" in safe_cfg and "password_hash" in safe_cfg["dashboard"]:
            safe_cfg["dashboard"]["password_hash"] = "***"
        if "password" in safe_cfg:
            safe_cfg["password"] = "***"
    print("Config:")
    print(json.dumps(safe_cfg, indent=2))
    print(f"\nActive network: {cfg.get('active_network', 'main')} ({active_ssid(cfg)})")
    print(f"Staged profile SSID: {broadcast['configured_ssid']}")
    print(f"Currently broadcasting SSID: {broadcast['broadcast_ssid']}")
    print(f"Broadcast verdict: {broadcast['verdict']}")
    if broadcast['broadcast_ssid'] != broadcast['configured_ssid']:
        print("WARNING: staged profile and live broadcast differ. Restart/toggle Internet Sharing to apply the staged SSID.")
    print("macOS SSID limit: one hotspot SSID can be active at a time; Main and Guest are switchable profiles, not simultaneous networks.")
    print(f"Source mode: {source_mode(cfg)} via {source_interface(cfg)}")
    print(f"Loopback alias present: {loop_ok}")
    print(f"Detected Wi-Fi device: {wifi or 'unknown'}")
    print(f"Configured Wi-Fi device: {cfg.get('wifi_interface')}")
    print(f"Internet Sharing active: {loaded}")
    print(f"launchctl loaded: {sharing['launch_loaded']}")
    bridge = sharing.get("bridge", {})
    print(f"Hotspot bridge: {bridge.get('name', 'bridge100')} active={bridge.get('active')} ip={bridge.get('ip') or 'unknown'} members={', '.join(bridge.get('members', [])) or 'none'}")
    if sharing.get("evidence"):
        print("Internet Sharing evidence:")
        for item in sharing["evidence"]:
            print(f"  - {item}")
    print("\nNAT plist summary:")
    print(json.dumps(nat, indent=2, default=str)[:4000])
    if not loaded and launch_text.strip():
        print("\nlaunchctl detail:")
        print(launch_text.strip()[:2000])


def plan():
    cfg = load_config()
    print("Planned Local Hotspot Setup")
    print(f"Active network: {cfg.get('active_network', 'main')}")
    print(f"Main SSID: {cfg['main']['ssid']}")
    print(f"Guest SSID: {cfg['guest']['ssid']} ({'enabled/profile active' if cfg.get('active_network') == 'guest' else 'available, not active'})")
    print(f"Security: {cfg['security']}")
    print(f"Main password: {'set' if cfg['main'].get('password') else 'NOT SET'}")
    print(f"Guest password: {'set' if cfg['guest'].get('password') else 'NOT SET'}")
    print(f"Wi-Fi/AP interface: {cfg['wifi_interface']}")
    print(f"Source mode: {source_mode(cfg)} via {source_interface(cfg)}")
    print(f"Loopback local source: {cfg['loopback']['cidr']}")
    print(f"Active subnet target: {active_subnet(cfg)}")
    print(f"Guest firewall: {cfg.get('firewall', {}).get('enabled', True)} via pf anchor {PF_ANCHOR_NAME}")
    print("Start is blocked unless --apply --confirm ENABLE is supplied.")


def open_settings():
    if OPEN_SCRIPT.exists():
        run(["/usr/bin/osascript", str(OPEN_SCRIPT)], check=True)
    else:
        run(["/usr/bin/open", "x-apple.systempreferences:com.apple.Sharing-Settings.extension"], check=True)


def main():
    parser = argparse.ArgumentParser(
        description="Luminet local-first WiFi management",
        epilog=(
            "Switching note: macOS Internet Sharing can broadcast only one hotspot SSID at a time. "
            "Use 'hotspot switch main' or 'hotspot switch guest' to stage the desired profile, then run configure/start or toggle Internet Sharing in System Settings."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("plan")
    st = sub.add_parser("status"); st.add_argument("--show-secret", action="store_true")
    sub.add_parser("interfaces")
    sub.add_parser("dashboard")

    sc = sub.add_parser("set-config")
    sc.add_argument("--ssid"); sc.add_argument("--guest-ssid"); sc.add_argument("--wifi-interface"); sc.add_argument("--upstream-interface")
    sc.add_argument("--subnet"); sc.add_argument("--guest-subnet"); sc.add_argument("--password"); sc.add_argument("--guest-password")
    sc.add_argument("--source-mode", choices=["loopback", "interface"])

    gp = sub.add_parser("generate-password"); gp.add_argument("--length", type=int, default=32); gp.add_argument("--guest", action="store_true"); gp.add_argument("--main", action="store_true")
    rp = sub.add_parser("rotate-password"); rp.add_argument("profile", choices=["main", "guest", "dashboard"]); rp.add_argument("--length", type=int, default=32); rp.add_argument("--show", action="store_true")
    cfgp = sub.add_parser("configure"); cfgp.add_argument("--apply", action="store_true"); cfgp.add_argument("--confirm", default="")
    lp = sub.add_parser("setup-loopback"); lp.add_argument("--apply", action="store_true"); lp.add_argument("--confirm", default="")
    rlp = sub.add_parser("remove-loopback"); rlp.add_argument("--apply", action="store_true"); rlp.add_argument("--confirm", default="")

    start = sub.add_parser("start", help="Start/restart macOS Internet Sharing using the active profile; live use requires --apply --confirm ENABLE"); start.add_argument("--apply", action="store_true"); start.add_argument("--confirm", default="")
    stop = sub.add_parser("stop", help="Stop macOS Internet Sharing; live use requires --apply --confirm DISABLE"); stop.add_argument("--apply", action="store_true"); stop.add_argument("--confirm", default="")
    switchp = sub.add_parser("switch", help="Stage Main or Guest as the active SSID profile. One SSID can broadcast at a time on macOS."); switchp.add_argument("target", choices=["main", "guest"])
    guest = sub.add_parser("guest", help="Compatibility profile commands. Prefer: hotspot switch main|guest"); guest.add_argument("action", choices=["enable", "disable", "status", "test"])
    sub.add_parser("devices").add_argument("--json", action="store_true")
    mon = sub.add_parser("monitor"); mon.add_argument("--interval", type=int); mon.add_argument("--notify", action="store_true"); mon.add_argument("--once", action="store_true")
    sub.add_parser("learn-devices")
    logs = sub.add_parser("logs"); logs.add_argument("--recent", action="store_true"); logs.add_argument("--limit", type=int, default=40)
    fw = sub.add_parser("firewall"); fw.add_argument("action", choices=["plan", "apply", "remove", "status"]); fw.add_argument("--apply", action="store_true"); fw.add_argument("--confirm", default="")
    secp = sub.add_parser("security"); secsub = secp.add_subparsers(dest="security_cmd", required=True); secsub.add_parser("status"); par = secsub.add_parser("paranoid"); par.add_argument("action", choices=["enable", "disable", "status"]); par.add_argument("--apply-firewall", action="store_true"); certp = secsub.add_parser("cert"); certp.add_argument("action", choices=["generate"]); secsub.add_parser("learn-devices")
    lkp = sub.add_parser("lockdown"); lksub = lkp.add_subparsers(dest="lockdown_cmd", required=True); lke = lksub.add_parser("enable"); lke.add_argument("--no-firewall", action="store_true"); lksub.add_parser("disable"); lksub.add_parser("status")
    sub.add_parser("open-settings")

    args = parser.parse_args()
    cfg = load_config()

    if args.cmd == "plan": plan()
    elif args.cmd == "status": status(show_secret=args.show_secret)
    elif args.cmd == "interfaces": print(discover_interfaces())
    elif args.cmd == "dashboard":
        os.execv(sys.executable, [sys.executable, str(PROJECT_DIR / "scripts" / "dashboard.py")])
    elif args.cmd == "set-config":
        if args.ssid: cfg["main"]["ssid"] = args.ssid
        if args.guest_ssid: cfg["guest"]["ssid"] = args.guest_ssid
        if args.wifi_interface: cfg["wifi_interface"] = args.wifi_interface
        if args.upstream_interface: cfg["upstream_interface"] = args.upstream_interface
        if args.subnet: cfg["main"]["subnet"] = args.subnet
        if args.guest_subnet: cfg["guest"]["subnet"] = args.guest_subnet
        if args.password: cfg["main"]["password"] = args.password
        if args.guest_password: cfg["guest"]["password"] = args.guest_password
        if args.source_mode: cfg["source_mode"] = args.source_mode
        save_config(cfg)
        print(f"Updated {CONFIG_PATH}")
    elif args.cmd == "rotate-password":
        rotate_password(args.profile, length=args.length, show=args.show)
    elif args.cmd == "generate-password":
        if args.length < 24: raise SystemExit("Password length must be at least 24")
        if args.guest and not args.main:
            cfg["guest"]["password"] = generate_password(args.length)
            event = "guest_password_generated"
        else:
            cfg["main"]["password"] = generate_password(args.length)
            event = "main_password_generated"
        save_config(cfg, event=event)
        print(f"Generated password and saved to {CONFIG_PATH} with chmod 600")
        print("Use status --show-secret only if you need to read it.")
    elif args.cmd == "configure":
        if args.apply: require_confirm("CONFIGURE", args.confirm)
        write_nat_plist(cfg, apply=args.apply)
    elif args.cmd == "setup-loopback":
        if args.apply: require_confirm("LOOPBACK", args.confirm)
        ensure_loopback_alias(cfg, apply=args.apply)
    elif args.cmd == "remove-loopback":
        if args.apply: require_confirm("REMOVE_LOOPBACK", args.confirm)
        remove_loopback_alias(cfg, apply=args.apply)
    elif args.cmd == "start":
        if args.apply:
            require_confirm("ENABLE", args.confirm)
            write_nat_plist(cfg, apply=True)
            if firewall_enabled_for_active_profile(cfg):
                firewall_apply(cfg, apply=True)
        start_service(apply=args.apply)
    elif args.cmd == "stop":
        if args.apply: require_confirm("DISABLE", args.confirm)
        stop_service(apply=args.apply)
    elif args.cmd == "switch":
        switch_profile(args.target)
    elif args.cmd == "guest":
        if args.action == "status":
            nat = read_nat_plist()
            _, broadcast = live_broadcast_summary(cfg, nat=nat)
            payload = {
                "active_network": cfg.get("active_network"),
                "main": {**cfg.get("main", {}), "password": "***"},
                "guest": {**cfg.get("guest", {}), "password": "***"},
                "currently_broadcasting_ssid": broadcast["broadcast_ssid"],
                "staged_ssid": broadcast["configured_ssid"],
                "broadcast_verdict": broadcast["verdict"],
                "macos_ssid_limit": "one hotspot SSID can be active at a time; Main and Guest are switchable profiles",
            }
            print(json.dumps(payload, indent=2))
        elif args.action == "test":
            guest_test_dryrun()
        else:
            target = "guest" if args.action == "enable" else "main"
            print(f"Compatibility command: guest {args.action}. Prefer: ./bin/hotspot switch {target}")
            switch_profile(target)
    elif args.cmd == "devices": connected_devices(json_out=args.json)
    elif args.cmd == "learn-devices": learn_current_devices()
    elif args.cmd == "monitor": monitor(interval=args.interval, notify_new=args.notify, once=args.once)
    elif args.cmd == "logs": show_logs(recent=args.recent, limit=args.limit)
    elif args.cmd == "firewall":
        if args.action == "status": firewall_status()
        elif args.action == "plan": firewall_plan(cfg)
        elif args.action == "apply":
            if args.apply: require_confirm("FIREWALL", args.confirm)
            firewall_apply(cfg, apply=args.apply)
        elif args.action == "remove":
            if args.apply: require_confirm("FIREWALL_REMOVE", args.confirm)
            firewall_remove(apply=args.apply)
    elif args.cmd == "security":
        if args.security_cmd == "status": security_status()
        elif args.security_cmd == "learn-devices": learn_current_devices()
        elif args.security_cmd == "cert" and args.action == "generate": generate_dashboard_cert()
        elif args.security_cmd == "paranoid":
            if args.action == "enable": enable_paranoid_mode(apply=args.apply_firewall)
            elif args.action == "disable": disable_paranoid_mode()
            else: security_status()
    elif args.cmd == "open-settings": open_settings()
    elif args.cmd == "lockdown":
        if args.lockdown_cmd == "enable":
            enable_lockdown(apply_firewall=not args.no_firewall)
        elif args.lockdown_cmd == "disable":
            disable_lockdown()
        elif args.lockdown_cmd == "status":
            lockdown_status()


if __name__ == "__main__":
    main()
