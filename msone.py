#!/usr/bin/env python3
import json,os,urllib.request,urllib.error
base=os.environ.get('BUILDMODE_DISPATCHER_URL','http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local')
body=json.dumps({'user_id':'snapgpt-msone@armorerlabs.com','host_url':'http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','project_path':'../../../../health','force':True},separators=(',',':')).encode()
req=urllib.request.Request(base+'/session/init',data=body,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
try:
 with urllib.request.urlopen(req,timeout=20) as r: print('STATUS',r.status); print(r.read(20000).decode('utf-8','replace'))
except urllib.error.HTTPError as e: print('STATUS',e.code); print(e.read(20000).decode('utf-8','replace'))
except Exception as e: print('ERR',repr(e))
