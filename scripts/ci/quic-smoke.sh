#!/usr/bin/env bash
set -euo pipefail

MLVPN="${MLVPN:-./src/mlvpn}"
WORKDIR="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

if [ ! -x "$MLVPN" ]; then
    echo "mlvpn binary not found at $MLVPN" >&2
    exit 1
fi

if [ ! -e /dev/net/tun ]; then
    sudo mkdir -p /dev/net
    sudo mknod /dev/net/tun c 10 200
    sudo chmod 0666 /dev/net/tun
fi
if command -v modprobe >/dev/null 2>&1; then
    sudo modprobe tun 2>/dev/null || true
fi
if [ ! -c /dev/net/tun ]; then
    echo "TUN device unavailable; skipping QUIC smoke test" >&2
    exit 0
fi

if ! id -u mlvpn &>/dev/null; then
    sudo useradd -r -d /run/mlvpn -s /usr/sbin/nologin mlvpn
fi
sudo mkdir -p /run/mlvpn/dev
if [ ! -c /run/mlvpn/dev/urandom ]; then
    sudo mknod -m 666 /run/mlvpn/dev/urandom c 1 9
fi
if [ ! -c /run/mlvpn/dev/random ]; then
    sudo mknod -m 666 /run/mlvpn/dev/random c 1 8
fi
sudo chown -R mlvpn:mlvpn /run/mlvpn

cat >"$WORKDIR/server.conf" <<'EOF'
[general]
mode = "server"
transport = "quic"
mtu = 1444
tuntap = "tun"
interface_name = "mlvpn0"
timeout = 30
password = "ci-quic-test"

[link]
bindhost = "127.0.0.1"
bindport = "15080"
EOF

cat >"$WORKDIR/client.conf" <<'EOF'
[general]
mode = "client"
transport = "quic"
mtu = 1444
tuntap = "tun"
interface_name = "mlvpn1"
timeout = 30
password = "ci-quic-test"

[link]
remotehost = "127.0.0.1"
remoteport = "15080"
EOF

chmod 0600 "$WORKDIR/server.conf" "$WORKDIR/client.conf"

FAIL_PAT='\[CRIT|fatal|unable to chroot|TLS init failed|incorrect password|quic_create|unable to open /dev/net/tun|failed to open|sendmsg failed|ngtcp2_conn_'
SERVER_READY_PAT='\[INFO/quic\].*QUIC transport enabled'

sudo stdbuf -oL -eL env MLVPN_SKIP_CHROOT=1 MLVPN_QUIC_INSECURE=1 "$MLVPN" --debug -v -c "$WORKDIR/server.conf" -u mlvpn \
    >"$WORKDIR/server.log" 2>&1 &

for _ in $(seq 1 30); do
    if grep -qE "$SERVER_READY_PAT" "$WORKDIR/server.log"; then
        break
    fi
    if grep -qiE "$FAIL_PAT" "$WORKDIR/server.log"; then
        echo "Server failed to start:" >&2
        cat "$WORKDIR/server.log" >&2
        exit 1
    fi
    sleep 1
done

if ! grep -qE "$SERVER_READY_PAT" "$WORKDIR/server.log"; then
    echo "Server did not start QUIC transport in time:" >&2
    cat "$WORKDIR/server.log" >&2
    exit 1
fi

sleep 1

sudo stdbuf -oL -eL env MLVPN_SKIP_CHROOT=1 MLVPN_QUIC_INSECURE=1 "$MLVPN" --debug -v -c "$WORKDIR/client.conf" -u mlvpn \
    >"$WORKDIR/client.log" 2>&1 &

for _ in $(seq 1 30); do
    if grep -q "QUIC session established" "$WORKDIR/client.log"; then
        echo "QUIC handshake succeeded"
        exit 0
    fi
    if grep -qiE "$FAIL_PAT" "$WORKDIR/server.log" "$WORKDIR/client.log"; then
        break
    fi
    sleep 1
done

echo "QUIC smoke test failed. Client log:" >&2
cat "$WORKDIR/client.log" >&2
echo "Server log:" >&2
cat "$WORKDIR/server.log" >&2
exit 1
