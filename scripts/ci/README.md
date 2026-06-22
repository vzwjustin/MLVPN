# MLVPN continuous integration scripts

## QUIC smoke test (`quic-smoke.sh`)

End-to-end handshake test for the optional QUIC transport. Used as a hard gate in
the GitHub Actions QUIC build job (`.github/workflows/build.yml`).

### What it does

1. Creates temporary server and client `mlvpn.conf` files with `transport = "quic"`
2. Installs TLS fixtures from `quic-fixtures/` under `/run/mlvpn/quic-ci`
3. Starts a QUIC server, waits for `QUIC transport enabled` (or `created interface`)
4. Starts a QUIC client and waits up to 30 seconds for `QUIC session established`
5. Prints both logs and exits non-zero on failure

### Requirements

- Built `mlvpn` binary with `./configure --enable-quic` (default path: `./src/mlvpn`)
- `/dev/net/tun` (the script creates the device node if missing)
- `sudo` for TUN setup, fixture install, and running as root

### Environment variables

| Variable | Purpose |
|----------|---------|
| `MLVPN` | Path to the `mlvpn` binary (default: `./src/mlvpn`) |
| `MLVPN_SKIP_CHROOT=1` | Skip privsep chroot so CI can access system RNG and fixtures |
| `MLVPN_QUIC_INSECURE=1` | **CI only.** Load PEM fixtures instead of password-derived TLS keys |
| `MLVPN_QUIC_FIXTURES` | Directory containing `server.crt` and `server.key` for CI |

`MLVPN_QUIC_INSECURE` and `MLVPN_QUIC_FIXTURES` exist for automated testing only.
Production deployments must rely on the shared `password` to derive TLS credentials.

### Local run

```sh
./autogen.sh
./configure --enable-quic
make -j"$(nproc)"
chmod +x scripts/ci/quic-smoke.sh
scripts/ci/quic-smoke.sh
```

### TLS fixtures

`quic-fixtures/server.crt` and `quic-fixtures/server.key` are self-signed PEM files
used when `MLVPN_QUIC_INSECURE=1` is set. They are copied into `/run/mlvpn/quic-ci`
at test time and are not used in normal operation.
