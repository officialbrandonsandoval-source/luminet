#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

printf '== syntax: python ==\n'
python3 -m py_compile scripts/hotspot.py scripts/dashboard.py scripts/hotspot_nl.py

printf '== syntax: shell ==\n'
zsh -n bin/install
zsh -n bin/emergency-network-reset
zsh -n bin/reset-network

printf '== config example JSON ==\n'
python3 -m json.tool config/hotspot.example.json >/dev/null

printf '== installer safe bootstrap ==\n'
./bin/install >/tmp/luminet-install-smoke.log
sed -n '1,80p' /tmp/luminet-install-smoke.log

printf '== safe CLI commands ==\n'
./bin/hotspot -h >/tmp/luminet-help-smoke.log
./bin/hotspot switch guest >/tmp/luminet-switch-guest-smoke.log
./bin/hotspot guest status >/tmp/luminet-guest-status-smoke.log

grep -q 'switch' /tmp/luminet-help-smoke.log
grep -q 'Profile switch staged' /tmp/luminet-switch-guest-smoke.log
grep -q 'currently_broadcasting_ssid' /tmp/luminet-guest-status-smoke.log

printf '== safety: tracked content scan ==\n'
python3 - <<'PY'
import pathlib, re, subprocess, sys
files = subprocess.check_output(['git','ls-files'], text=True).splitlines()
patterns = {
    'private_key': re.compile(r'BEGIN (RSA|OPENSSH|PRIVATE|EC) KEY'),
    'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'github_token': re.compile(r'(ghp_|github_pat_|gho_)[A-Za-z0-9_]{20,}'),
    'openai_key': re.compile(r'\bsk-[A-Za-z0-9]{20,}'),
    'real_pbkdf2_hash': re.compile(r'pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=._-]+\$[A-Za-z0-9+/=._-]+'),
    'mac_address': re.compile(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b'),
    'personal_path': re.compile(r'/Users/brandonsandoval'),
}
allow = {
    ('config/hotspot.example.json', 'pbkdf2_sha256$ITERATIONS$SALT$DIGEST_REPLACE_LOCALLY'),
}
findings=[]
for file in files:
    p=pathlib.Path(file)
    if not p.is_file(): continue
    text=p.read_text(errors='ignore')
    for line_no,line in enumerate(text.splitlines(), 1):
        for name,pat in patterns.items():
            if pat.search(line):
                if (file, line.strip()) in allow:
                    continue
                findings.append(f'{name}: {file}:{line_no}: {line[:180]}')
if findings:
    print('\n'.join(findings))
    sys.exit(2)
print('PASS')
PY

printf 'Smoke tests passed.\n'
