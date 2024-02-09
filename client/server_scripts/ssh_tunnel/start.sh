#!/bin/sh

echo "Container startup (sshd)"
exec /usr/sbin/sshd -D -e
