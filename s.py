import socket
names=['lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','mongo.canv2-sl-app-launcher.svc.cluster.local','mongodb.canv2-sl-app-launcher.svc.cluster.local','redis.canv2-sl-app-launcher.svc.cluster.local','slds.canv2-sl-app-launcher.svc.cluster.local','tectonic.canv2-sl-app-launcher.svc.cluster.local','pygencc-workers.canv2-snapgpt-workspace.svc.cluster.local','lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local']
ports=[80,443,8080,8081,27017,6379]
for n in names:
 try: ips=sorted(set(x[4][0] for x in socket.getaddrinfo(n,None)))
 except Exception as e: print(n,'DNS',type(e).__name__); continue
 print(n,'DNS',','.join(ips))
 for ip in ips:
  for p in ports:
   s=socket.socket();s.settimeout(1)
   try:
    r=s.connect_ex((ip,p)); print(n,ip,p,'open' if r==0 else 'closed')
   finally:s.close()
