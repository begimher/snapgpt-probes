#!/bin/sh
set -x
mkdir -p /tmp/ns /tmp/mnt
mount -t tmpfs tmpfs /tmp/ns
mknod /tmp/ns/nvme b 259 1
ls -l /tmp/ns/nvme
mount -t xfs /tmp/ns/nvme /tmp/mnt
ls -la /tmp/mnt | head -30
