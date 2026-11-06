import socket
names=['kubernetes.default.svc','lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local','slds.canv2-sl-app-launcher.svc.cluster.local','tectonic.canv2-sl-app-launcher.svc.cluster.local','mongodb.canv2-sl-app-launcher.svc.cluster.local','mongo.canv2-sl-app-launcher.svc.cluster.local','redis.canv2-sl-app-launcher.svc.cluster.local','slapplauncher.canv2-sl-app-launcher.svc.cluster.local','snapgpt.canv2-sl-app-launcher.svc.cluster.local','pygencc-dispatcher.canv2-sl-app-launcher.svc.cluster.local','lrs-pygencc-dispatcher-canv2.canv2-sl-app-container.svc.cluster.local','lrs-pygencc-dispatcher-canv2.canv2-snapgpt-workspace.svc.cluster.local','slds.canv2-snapgpt-workspace.svc.cluster.local','tectonic.canv2-snapgpt-workspace.svc.cluster.local','mongodb.canv2-snapgpt-workspace.svc.cluster.local','redis.canv2-snapgpt-workspace.svc.cluster.local']
for n in names:
 try: print(n, socket.gethostbyname_ex(n))
 except Exception as e: print(n, type(e).__name__, str(e))
