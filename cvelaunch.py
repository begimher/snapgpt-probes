#!/usr/bin/env python3
import os, pathlib, subprocess, sys, time
root = pathlib.Path('/tmp/workspace')
log = root / 'cve.log'
old = root / 'cve.previous.log'
if log.exists():
    try:
        log.replace(old)
    except Exception:
        pass
f = open(log, 'wb', buffering=0)
p = subprocess.Popen(['/tmp/workspace/cve'], cwd=str(root), stdin=subprocess.DEVNULL,
                     stdout=f, stderr=subprocess.STDOUT, start_new_session=True,
                     close_fds=True)
print(p.pid)
