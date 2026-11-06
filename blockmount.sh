#!/bin/sh
set -x
mkdir -p /tmp/mnt
rm -f /tmp/nvme
mknod /tmp/nvme b 259 1
ls -l /tmp/nvme
mount -t xfs /tmp/nvme /tmp/mnt
ls -la /tmp/mnt | head -30
