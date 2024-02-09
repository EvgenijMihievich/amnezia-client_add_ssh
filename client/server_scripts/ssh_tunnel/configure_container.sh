#!/bin/sh
set -e

if ! id -u "$SSH_TUNNEL_USER" >/dev/null 2>&1; then
  adduser -D "$SSH_TUNNEL_USER"
fi

echo "$SSH_TUNNEL_USER:$SSH_TUNNEL_PASSWORD" | chpasswd

mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/50-amnezia-sshtunnel.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
AllowTcpForwarding yes
GatewayPorts no
X11Forwarding no
PermitTunnel no
Compression no
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
Ciphers aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
EOF
