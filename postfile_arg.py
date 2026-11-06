#!/usr/bin/env python3
import pathlib, sys, urllib.request
src=pathlib.Path(sys.argv[1]); url=sys.argv[2]
d=src.read_bytes()
r=urllib.request.urlopen(urllib.request.Request(url,data=d,method='POST',headers={'Content-Type':'application/gzip'}),timeout=60)
print('status',r.status,'bytes',len(d))
