#!/usr/bin/env python3
"""Hardened local-first Luminet hotspot dashboard.

Security model:
- Local bind only: active Internet Sharing bridge first, then localhost fallback.
- Form login with signed random sessions and 5 minute inactivity timeout.
- HTTP Basic Auth remains as a CLI/API fallback, but all attempts are logged.
- Rate limiting and failed-login lockout are enforced per client IP.
- Optional self-signed HTTPS is supported from config/dashboard.https.
"""
import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import ssl
import subprocess
import sys
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

PROJECT_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_DIR / "config" / "hotspot.json"
HOTSPOT = PROJECT_DIR / "bin" / "hotspot"
LOG_DIR = PROJECT_DIR / "logs"
DASHBOARD_AUTH_LOG = LOG_DIR / "dashboard-auth.jsonl"

SESSIONS = {}
RATE = {}
FAILED = {}


def now():
    return int(time.time())


def load_config():
    return json.loads(CONFIG_PATH.read_text())


def run_hotspot(args, timeout=20):
    proc = subprocess.run([str(HOTSPOT)] + args, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def log_auth(event, client, username="", ok=False, reason=""):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, "client": client, "username": username, "ok": ok, "reason": reason}
    with DASHBOARD_AUTH_LOG.open("a") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")


def safe_config(cfg):
    c = json.loads(json.dumps(cfg))
    for key in ("main", "guest"):
        if key in c and "password" in c[key]:
            c[key]["password"] = "***"
    if "dashboard" in c:
        if "password" in c["dashboard"]:
            c["dashboard"]["password"] = "***"
        if "password_hash" in c["dashboard"]:
            c["dashboard"]["password_hash"] = "***"
    return c


def verify_password(password, stored_hash):
    try:
        algo, iterations, salt, digest = stored_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations)).hex()
        return hmac.compare_digest(candidate, digest)
    except Exception:
        return False


def dashboard_password_ok(cfg, password):
    dash = cfg.get("dashboard", {})
    if dash.get("password_hash"):
        return verify_password(password, dash["password_hash"])
    legacy = dash.get("password", "")
    return bool(legacy) and hmac.compare_digest(password, legacy)


def bridge_host():
    proc = subprocess.run(["/sbin/ifconfig", "bridge100"], capture_output=True, text=True)
    text = proc.stdout + proc.stderr
    if proc.returncode != 0 or "status: active" not in text:
        return ""
    match = re.search(r"\binet\s+([0-9.]+)\s+netmask", text)
    return match.group(1) if match else ""


def status_value(status_text, label, default="Unknown"):
    for line in status_text.splitlines():
        if line.startswith(label + ":"):
            return line.split(":", 1)[1].strip()
    return default


def parse_devices(devices_text):
    try:
        rows = json.loads(devices_text) if devices_text.strip().startswith("[") else []
    except Exception:
        rows = []
    return rows if isinstance(rows, list) else []


def dashboard_policy(cfg):
    dash = cfg.get("dashboard", {})
    rate = dash.get("rate_limit", {})
    return {
        "session_timeout": int(dash.get("session_timeout_seconds", 300)),
        "window": int(rate.get("window_seconds", 60)),
        "max_requests": int(rate.get("max_requests", 90)),
        "max_failed": int(rate.get("max_failed_logins", 5)),
        "lockout": int(rate.get("lockout_seconds", 300)),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "LuminetHotspotDashboard/3.0-hardened"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_ip(), self.log_date_time_string(), fmt % args))

    def client_ip(self):
        return self.client_address[0]

    def policy(self):
        return dashboard_policy(load_config())

    def rate_limited(self):
        client = self.client_ip()
        p = self.policy()
        t = now()
        bucket = RATE.setdefault(client, [])
        RATE[client] = [x for x in bucket if t - x < p["window"]]
        RATE[client].append(t)
        if len(RATE[client]) > p["max_requests"]:
            log_auth("rate_limited", client, ok=False, reason="request_limit")
            self.send_text(429, "Too many requests. Slow down.\n")
            return True
        fail = FAILED.get(client)
        if fail and fail.get("locked_until", 0) > t:
            self.send_text(423, "Dashboard locked temporarily after failed logins.\n")
            return True
        return False

    def parse_cookie(self):
        raw = self.headers.get("Cookie", "")
        c = cookies.SimpleCookie()
        try:
            c.load(raw)
        except Exception:
            return {}
        return {k: v.value for k, v in c.items()}

    def session_ok(self):
        sid = self.parse_cookie().get("luminet_session", "")
        rec = SESSIONS.get(sid)
        if not sid or not rec:
            return False
        p = self.policy()
        if now() - rec.get("last_seen", 0) > p["session_timeout"]:
            SESSIONS.pop(sid, None)
            return False
        rec["last_seen"] = now()
        return True

    def basic_ok(self):
        cfg = load_config()
        dash = cfg.get("dashboard", {})
        expected_user = dash.get("username", "maximus")
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(header.split(" ", 1)[1]).decode()
            user, pw = raw.split(":", 1)
        except Exception:
            log_auth("basic_login", self.client_ip(), ok=False, reason="malformed_header")
            return False
        ok = user == expected_user and dashboard_password_ok(cfg, pw)
        log_auth("basic_login", self.client_ip(), username=user, ok=ok, reason="ok" if ok else "bad_credentials")
        if not ok:
            self.record_failed_login()
        return ok

    def auth_ok(self):
        return self.session_ok() or self.basic_ok()

    def record_failed_login(self):
        client = self.client_ip()
        p = self.policy()
        rec = FAILED.setdefault(client, {"count": 0, "locked_until": 0})
        rec["count"] += 1
        if rec["count"] >= p["max_failed"]:
            rec["locked_until"] = now() + p["lockout"]
            log_auth("login_lockout", client, ok=False, reason=f"{rec['count']} failures")

    def require_auth(self):
        if self.rate_limited():
            return False
        if self.auth_ok():
            return True
        if self.path.startswith("/api/"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Luminet"')
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Authentication required.\n")
            return False
        self.redirect("/login")
        return False

    def security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline' 'self'; script-src 'unsafe-inline' 'self'; img-src 'self' data:")

    def send_text(self, code, text, content_type="text/plain", extra_headers=None):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.security_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.security_headers()
        self.end_headers()

    def do_GET(self):
        if self.rate_limited():
            return
        if self.path.startswith("/login"):
            return self.render_login()
        if self.path.startswith("/logout"):
            sid = self.parse_cookie().get("luminet_session", "")
            SESSIONS.pop(sid, None)
            return self.send_text(200, self.login_html("Logged out."), "text/html", {"Set-Cookie": "luminet_session=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/"})
        if not self.require_auth():
            return
        if self.path.startswith("/api/status"):
            code, out, err = run_hotspot(["status"])
            return self.send_text(200 if code == 0 else 500, out + err)
        if self.path.startswith("/api/devices"):
            code, out, err = run_hotspot(["devices", "--json"])
            return self.send_text(200 if code == 0 else 500, out + err, "application/json")
        if self.path.startswith("/api/logs"):
            code, out, err = run_hotspot(["logs", "--recent", "--limit", "80"])
            return self.send_text(200 if code == 0 else 500, out + err)
        if self.path.startswith("/api/security"):
            code, out, err = run_hotspot(["security", "status"])
            return self.send_text(200 if code == 0 else 500, out + err)
        return self.render_home()

    def do_POST(self):
        if self.rate_limited():
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        data = parse_qs(self.rfile.read(length).decode())
        if self.path.startswith("/login"):
            return self.handle_login(data)
        if not self.require_auth():
            return
        action = data.get("action", [""])[0]
        confirm = data.get("confirm", [""])[0].strip()
        cfg = load_config()
        allow_real = bool(cfg.get("dashboard", {}).get("allow_real_controls", False))
        routes = {
            "refresh_status": ["status"],
            "security_status": ["security", "status"],
            "plan": ["plan"],
            "dry_start": ["start"],
            "dry_stop": ["stop"],
            "monitor_once": ["monitor", "--once"],
            "learn_devices": ["security", "learn-devices"],
            "switch_guest": ["switch", "guest"],
            "switch_main": ["switch", "main"],
            "profile_guest": ["switch", "guest"],
            "profile_main": ["switch", "main"],
            "firewall_plan": ["firewall", "plan"],
            "firewall_status": ["firewall", "status"],
        }
        real_routes = {
            "real_start": (["start", "--apply", "--confirm", confirm], "ENABLE"),
            "real_stop": (["stop", "--apply", "--confirm", confirm], "DISABLE"),
            "real_firewall": (["firewall", "apply", "--apply", "--confirm", confirm], "FIREWALL"),
        }
        if action in routes:
            code, out, err = run_hotspot(routes[action], timeout=60)
            return self.result_page(action, code, out, err)
        if action in real_routes:
            if not allow_real:
                return self.result_page(action, 2, "", "Real controls are disabled in dashboard config. Use CLI confirmation tokens for live network changes.")
            cmd, expected = real_routes[action]
            if confirm != expected:
                return self.result_page(action, 2, "", f"Refusing. Required confirmation token: {expected}")
            code, out, err = run_hotspot(cmd, timeout=120)
            return self.result_page(action, code, out, err)
        return self.result_page(action or "unknown", 2, "", "Unknown dashboard action")

    def handle_login(self, data):
        cfg = load_config()
        dash = cfg.get("dashboard", {})
        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]
        expected_user = dash.get("username", "maximus")
        ok = username == expected_user and dashboard_password_ok(cfg, password)
        log_auth("form_login", self.client_ip(), username=username, ok=ok, reason="ok" if ok else "bad_credentials")
        if not ok:
            self.record_failed_login()
            return self.render_login("Bad username or password.")
        FAILED.pop(self.client_ip(), None)
        sid = secrets.token_urlsafe(32)
        SESSIONS[sid] = {"client": self.client_ip(), "created": now(), "last_seen": now()}
        timeout = self.policy()["session_timeout"]
        self.send_response(303)
        self.send_header("Location", "/")
        self.security_headers()
        self.send_header("Set-Cookie", f"luminet_session={sid}; HttpOnly; SameSite=Strict; Max-Age={timeout}; Path=/")
        self.end_headers()

    def login_html(self, message=""):
        msg = f"<p class='danger'>{html.escape(message)}</p>" if message else ""
        return f"<!doctype html><html><head><title>Luminet Login</title><meta name='viewport' content='width=device-width, initial-scale=1'>{self.styles()}</head><body><main class='shell narrow'><section class='panel hero'><div><p class='eyebrow'>Hardened local access</p><h1>Luminet</h1><p class='muted'>Session expires after 5 minutes of inactivity. Failed logins are logged and locked out.</p>{msg}<form method='post' action='/login'><input name='username' placeholder='Username' autocomplete='username'><input name='password' type='password' placeholder='Password' autocomplete='current-password'><button>Log in</button></form></div></section></main></body></html>"

    def render_login(self, message=""):
        return self.send_text(200, self.login_html(message), "text/html")

    def result_page(self, action, code, out, err):
        tone = "ok" if code == 0 else "danger"
        body = f"""<!doctype html><html><head><title>Luminet Result</title><meta name='viewport' content='width=device-width, initial-scale=1'>{self.styles()}</head><body><main class='shell'><a class='back' href='/'>← Back to dashboard</a><section class='panel hero'><div><p class='eyebrow'>Action result</p><h1>{html.escape(action)}</h1><p class='{tone}'>Exit code: {code}</p></div></section><section class='panel'><h2>Command output</h2><pre>{html.escape(out + err)}</pre></section></main></body></html>"""
        self.send_text(200 if code == 0 else 500, body, "text/html")

    def styles(self):
        return """
        <style>
        :root{
          --bg:#03060B;--panel:#0B1220;--panel2:#101A2A;--line:#203147;
          --text:#EAF2FF;--muted:#8EA4BD;--blue:#16A3FF;--amber:#F5A623;
          --green:#39D98A;--red:#FF5C7A;--chip:#132338;
        }
        *{box-sizing:border-box}
        html{font-size:16px;-webkit-text-size-adjust:100%}
        body{margin:0;background:radial-gradient(circle at top left,#10233A 0,#03060B 42%,#020409 100%);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Inter',system-ui,sans-serif;line-height:1.45}
        .shell{width:min(1180px,calc(100vw - 32px));margin:0 auto;padding:28px 0 48px}
        .narrow{width:min(520px,calc(100vw - 32px))}
        .hero{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;background:linear-gradient(135deg,rgba(22,163,255,.18),rgba(245,166,35,.08)),var(--panel)}
        .panel{background:rgba(11,18,32,.9);border:1px solid var(--line);border-radius:22px;padding:20px;box-shadow:0 18px 60px rgba(0,0,0,.28);backdrop-filter:blur(10px);margin-bottom:16px}
        .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:16px;margin-top:16px}
        .span-4{grid-column:span 4}.span-5{grid-column:span 5}.span-7{grid-column:span 7}.span-8{grid-column:span 8}.span-12{grid-column:span 12}
        h1{font-size:clamp(34px,7vw,62px);line-height:.95;margin:6px 0 10px;letter-spacing:-.05em}
        h2{font-size:18px;margin:0 0 8px}.eyebrow{margin:0;color:var(--blue);font-weight:800;text-transform:uppercase;letter-spacing:.12em;font-size:12px}.muted{color:var(--muted)}
        .status-dot{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;background:rgba(57,217,138,.12);color:var(--green);font-weight:800;white-space:nowrap}.status-dot.off{background:rgba(255,92,122,.12);color:var(--red)}
        .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}.metric{background:var(--panel2);border:1px solid var(--line);border-radius:16px;padding:14px}.metric .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.metric .value{font-size:22px;font-weight:850;overflow-wrap:anywhere}
        .tip{border:1px solid var(--line);background:rgba(22,163,255,.08);border-radius:14px;padding:10px 12px}.tip.warn{background:rgba(245,166,35,.10);border-color:rgba(245,166,35,.32)}.tip.danger{background:rgba(255,92,122,.10);border-color:rgba(255,92,122,.32);color:#FFD5DE}
        form{display:grid;gap:10px}button,input{width:100%;border:1px solid var(--line);border-radius:14px;padding:13px 14px;background:var(--panel2);color:var(--text);font:inherit;min-height:48px}button{cursor:pointer;background:linear-gradient(135deg,var(--blue),#0876D8);border:0;font-weight:850}button.secondary{background:#152238;border:1px solid var(--line)}button.warning{background:linear-gradient(135deg,var(--amber),#B66F00);color:#120B00}button:focus,input:focus,a:focus{outline:3px solid rgba(22,163,255,.45);outline-offset:2px}
        .table-wrap{overflow:auto;border:1px solid var(--line);border-radius:16px}table{border-collapse:collapse;width:100%;min-width:760px}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.chip{display:inline-block;padding:4px 8px;border-radius:999px;background:var(--chip)}.chip.hotspot{color:var(--green)}.chip.warn{color:var(--amber)}
        pre{white-space:pre-wrap;word-break:break-word;max-height:420px;overflow:auto;background:#050A12;border:1px solid var(--line);border-radius:16px;padding:14px;font-size:12px;line-height:1.45}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.back{color:var(--blue);text-decoration:none}.footer{color:var(--muted);text-align:center}.ok{color:var(--green)}.danger{color:var(--red)}
        @media(max-width:900px){.span-4,.span-5,.span-7,.span-8{grid-column:span 12}.hero{display:block}.shell{width:min(100vw - 20px,1180px);padding:14px 0 32px}.panel{border-radius:18px;padding:16px}.cards{grid-template-columns:1fr 1fr}.hero .status-dot{margin-top:12px}}
        @media(max-width:560px){.cards{grid-template-columns:1fr}.metric .value{font-size:20px}h1{font-size:42px}.panel{padding:14px}.table-wrap{margin-left:-2px;margin-right:-2px}button,input{font-size:16px}.footer{text-align:left}}
        </style>
        """

    def render_home(self):
        cfg = load_config()
        code_s, status, err_s = run_hotspot(["status"], timeout=30)
        code_d, devices, err_d = run_hotspot(["devices", "--json"], timeout=20)
        code_l, logs, err_l = run_hotspot(["logs", "--recent", "--limit", "35"], timeout=20)
        code_sec, sec_status, err_sec = run_hotspot(["security", "status"], timeout=30)
        device_rows = parse_devices(devices)
        hotspot_rows = [d for d in device_rows if d.get("network") == "hotspot"]
        other_rows = [d for d in device_rows if d.get("network") != "hotspot"]
        active = status_value(status, "Internet Sharing active", "False") == "True"
        bridge = status_value(status, "Hotspot bridge", "Unknown")
        source = status_value(status, "Source mode", "Unknown")
        staged_ssid = status_value(status, "Staged profile SSID", "Unknown")
        broadcast_ssid = status_value(status, "Currently broadcasting SSID", "Unknown")
        broadcast_verdict = status_value(status, "Broadcast verdict", "Unknown")
        active_network = cfg.get("active_network", "main")
        profile = cfg.get(active_network, cfg.get("main", {}))
        ssid = profile.get("ssid", "Luminet")
        inactive_network = "guest" if active_network == "main" else "main"
        inactive_ssid = cfg.get(inactive_network, {}).get("ssid", "Luminet-Guest" if inactive_network == "guest" else "Luminet")
        mismatch = broadcast_ssid not in ("Unknown", staged_ssid) and broadcast_ssid != staged_ssid
        switch_warning = "macOS Internet Sharing can broadcast only one SSID at a time. Switching stages the target profile; apply configure/start or toggle Internet Sharing to make it broadcast."
        sec_cfg = cfg.get("security_hardening", {})
        paranoid = bool(sec_cfg.get("paranoid_mode", False))
        safe = html.escape(json.dumps(safe_config(cfg), indent=2))

        def row(d):
            name = d.get("name") or "Unnamed device"
            badge = "hotspot" if d.get("network") == "hotspot" else ""
            unknown = " warn" if d.get("network") == "hotspot" and "unknown" in d.get("vendor", "unknown") else ""
            return (f"<tr><td><span class='chip {badge}{unknown}'>{html.escape(d.get('role','Unknown'))}</span></td>"
                    f"<td>{html.escape(d.get('ip',''))}</td><td><b>{html.escape(name)}</b></td>"
                    f"<td><code>{html.escape(d.get('mac',''))}</code></td><td>{html.escape(d.get('vendor','unknown'))}</td><td>{html.escape(d.get('source',''))}</td></tr>")

        rows = "".join(row(d) for d in hotspot_rows + other_rows) or "<tr><td colspan='6'>No clients found yet. Connect a phone or laptop to the hotspot, then refresh.</td></tr>"
        status_class = "status-dot" if active else "status-dot off"
        status_text = "Online" if active else "Not detected"
        bind_host, bind_port = self.server.server_address
        scheme = "https" if isinstance(self.request, ssl.SSLSocket) else "http"
        dashboard_url = f"{scheme}://{bind_host}:{bind_port}"
        client_url = dashboard_url if not str(bind_host).startswith("127.") else f"Local Mac only: {scheme}://127.0.0.1:{bind_port}"
        mismatch_html = f"<p class='tip danger'>Live broadcast ({html.escape(broadcast_ssid)}) does not match staged profile ({html.escape(staged_ssid)}). Restart/toggle Internet Sharing to apply the staged SSID.</p>" if mismatch else ""
        switch_label = "Switch to Guest" if active_network == "main" else "Switch to Main"
        switch_action = "switch_guest" if active_network == "main" else "switch_main"
        body = f"""
        <!doctype html><html><head><title>Luminet Dashboard</title><meta name='viewport' content='width=device-width, initial-scale=1'><meta http-equiv='refresh' content='30'>{self.styles()}</head><body><main class='shell'>
        <section class='panel hero'><div><p class='eyebrow'>Hardened local-first network control</p><h1>Luminet</h1><p class='muted'>Private network control with session timeout, login protection, device monitoring, and hardened guest isolation.</p></div><div><span class='{status_class}'>● {status_text}</span><p class='muted'>Dashboard: {html.escape(dashboard_url)}</p><p><a class='back' href='/logout'>Logout</a></p></div></section>
        <section class='grid'>
          <div class='panel span-8'><div class='cards'><div class='metric'><div class='label'>Staged active SSID</div><div class='value'>{html.escape(staged_ssid)}</div></div><div class='metric'><div class='label'>Currently broadcasting</div><div class='value'>{html.escape(broadcast_ssid)}</div></div><div class='metric'><div class='label'>Profile</div><div class='value'>{html.escape(active_network.upper())}</div></div><div class='metric'><div class='label'>Hotspot clients</div><div class='value'>{len(hotspot_rows)}</div></div><div class='metric'><div class='label'>Mode</div><div class='value'>{html.escape(source)}</div></div><div class='metric'><div class='label'>Paranoid Mode</div><div class='value'>{'ON' if paranoid else 'OFF'}</div></div></div><p class='tip'>Broadcast verdict: {html.escape(broadcast_verdict)}</p>{mismatch_html}<p class='tip warn'>{html.escape(switch_warning)}</p></div>
          <div class='panel span-4'><h2>Network switch</h2><p class='muted'>Active profile: <b>{html.escape(active_network)}</b>. Other profile: {html.escape(inactive_network)} ({html.escape(inactive_ssid)}).</p><p class='tip warn'>Switch buttons stage config only. They do not apply firewall rules or restart Internet Sharing.</p><form method='post'><button class='warning' name='action' value='{switch_action}'>{html.escape(switch_label)}</button><button class='secondary' name='action' value='switch_main'>Switch to Main</button><button class='secondary' name='action' value='switch_guest'>Switch to Guest</button></form></div>
          <div class='panel span-4'><h2>Safe controls</h2><p class='muted'>Read-only or dry-run controls. Live changes remain gated.</p><form method='post'><button name='action' value='refresh_status'>Refresh status</button><button class='secondary' name='action' value='monitor_once'>Scan once</button><button class='secondary' name='action' value='security_status'>Security status</button><button class='secondary' name='action' value='learn_devices'>Learn current devices</button></form></div>
          <div class='panel span-12'><h2>Connected devices</h2><p class='muted'>Unknown hotspot clients should be treated as suspicious until learned. Device detection uses DHCP leases and ARP; randomized MACs can change.</p><div class='table-wrap'><table><thead><tr><th>Role</th><th>IP Address</th><th>Device Name</th><th>MAC Address</th><th>Vendor</th><th>Seen From</th></tr></thead><tbody>{rows}</tbody></table></div></div>
          <div class='panel span-5'><h2>Guest hardening</h2><p class='tip warn'>Guest Mode is a switchable profile, not a second simultaneous SSID. Review firewall plan before applying Guest live.</p><form method='post'><button class='secondary' name='action' value='firewall_plan'>Show hardened firewall plan</button><button class='secondary' name='action' value='firewall_status'>Firewall status</button></form><form method='post'><button class='warning' name='action' value='switch_guest'>Stage Guest profile</button><button class='secondary' name='action' value='switch_main'>Stage Main profile</button></form></div>
          <div class='panel span-7'><h2>Gated live controls</h2><p class='muted'>Disabled unless dashboard.allow_real_controls=true. Prefer CLI for live changes.</p><form method='post'><input name='confirm' placeholder='Required token: ENABLE, DISABLE, or FIREWALL'><button name='action' value='real_start'>Real start</button><button name='action' value='real_stop'>Real stop</button><button class='warning' name='action' value='real_firewall'>Apply firewall</button></form></div>
          <div class='panel span-7'><h2>Security status</h2><pre>{html.escape(sec_status + err_sec)}</pre></div><div class='panel span-5'><h2>Recent events</h2><pre>{html.escape(logs + err_l)}</pre></div>
          <div class='panel span-7'><h2>Status detail</h2><pre>{html.escape(status + err_s)}</pre></div><div class='panel span-5'><h2>Redacted config</h2><pre>{safe}</pre></div>
        </section><p class='footer'>Client URL note: {html.escape(client_url)} · Auto-refreshes every 30 seconds · Session expires after 5 minutes of inactivity.</p></main></body></html>
        """
        self.send_text(200, body, "text/html")


def main():
    cfg = load_config()
    dash = cfg.get("dashboard", {})
    configured_host = dash.get("host", "192.168.42.1")
    fallback = dash.get("fallback_host", "127.0.0.1")
    port = int(dash.get("port", 8080))
    candidates = []
    if configured_host:
        candidates.append((configured_host, "configured dashboard host"))
    bhost = bridge_host()
    if bhost and bhost not in [c[0] for c in candidates]:
        candidates.append((bhost, "active Internet Sharing bridge"))
    if fallback and fallback not in [c[0] for c in candidates]:
        candidates.append((fallback, "fallback local host"))

    last_error = None
    httpd = None
    reason = ""
    for host, why in candidates:
        try:
            httpd = ThreadingHTTPServer((host, port), Handler)
            reason = why
            break
        except OSError as exc:
            print(f"Could not bind {host}:{port} ({why}): {exc}")
            last_error = exc
    if httpd is None:
        raise SystemExit(f"Could not bind dashboard on any candidate host: {last_error}")

    https = dash.get("https", {})
    scheme = "http"
    if https.get("enabled"):
        cert = Path(https.get("cert_file", ""))
        key = Path(https.get("key_file", ""))
        if not cert.exists() or not key.exists():
            raise SystemExit("HTTPS enabled but certificate/key missing. Run ./bin/hotspot security cert generate")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    bound_host, bound_port = httpd.server_address
    print(f"Luminet dashboard running at {scheme}://{bound_host}:{bound_port}")
    print(f"Bind reason: {reason}")
    print("Use Ctrl-C to stop. Login attempts are logged to logs/dashboard-auth.jsonl.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Dashboard stopped.")


if __name__ == "__main__":
    main()
