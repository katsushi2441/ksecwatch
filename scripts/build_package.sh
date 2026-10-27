#!/usr/bin/env bash
# 配布用の zip を作る（設定の見本・説明書つき。社内の設定・台帳・記録は入れない）
set -euo pipefail
cd "$(dirname "$0")/.."
out=outputs/kurage-security-watch.zip; tmp=$(mktemp -d); d="$tmp/kurage-security-watch"
mkdir -p "$d/server" "$d/scripts"
cp server/agent_main.php "$d/server/"
cp scripts/{agent_call.py,deploy.py,watch.py,make_report.py,ksw_config.py} "$d/scripts/"
cp config.example.json .env.example policy.json requirements.txt README.md INSTALL.md CLAUDE.md AGENTS.md LICENSE "$d/"
printf 'config.json\n.env\ndata/\n.venv/\nrules/\noutputs/\n__pycache__/\n' > "$d/.gitignore"
grep -rq "FTP_PASS=.\|aixec/.env\|exbridge_jp\|kojima\|katsushi" "$d" && { echo "社内の設定の痕跡がある。止める" >&2; grep -rn "FTP_PASS=.\|aixec/.env\|exbridge_jp\|kojima\|katsushi" "$d" >&2; exit 1; } || true
mkdir -p outputs; rm -f "$out"; (cd "$tmp" && zip -qr - kurage-security-watch) > "$out"; rm -rf "$tmp"
unzip -l "$out"
