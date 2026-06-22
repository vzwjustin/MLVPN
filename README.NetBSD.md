Building mlvpn on NetBSD
========================

This port is NON WORKING at the moment.
(Some kind of tuntap issue)

Requirements
============

```shell
pkg_add pkgin
pkgin update
pkgin install mozilla-rootcerts git autoconf automake pkg-config libsodium libev
```

Build
=====
```shell
git clone https://github.com/zehome/MLVPN mlvpn
cd mlvpn
./autogen.sh
CPPFLAGS="-I/usr/pkg/include/ev" LDFLAGS="-L/usr/pkg/lib/ev" ./configure
make
```

## QUIC transport (optional)

If libngtcp2 and GnuTLS are installed, QUIC can be enabled at build time:

```shell
./configure --enable-quic
```

Set `transport = "quic"` in `mlvpn.conf` on both client and server. See `README.md`.

Install
=======

```shell
make install
```


Run
===
```shell
LD_LIBRARY_PATH=/usr/pkg/include/ev mlvpn ...
```
