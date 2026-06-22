#ifndef MLVPN_QUIC_TRANSPORT_H
#define MLVPN_QUIC_TRANSPORT_H

#include "includes.h"
#include <sys/socket.h>
#include <ev.h>

#define MLVPN_QUIC_UDP_PAYLOAD 2048

struct mlvpn_tunnel_s;

typedef void (*mlvpn_quic_data_cb)(struct mlvpn_tunnel_s *tun,
                                   const uint8_t *data, size_t len);
typedef void (*mlvpn_quic_connected_cb)(struct mlvpn_tunnel_s *tun);

struct mlvpn_quic_ctx;

struct mlvpn_quic_ctx *
mlvpn_quic_create(struct mlvpn_tunnel_s *tun, int server_mode, int fd,
                  const struct sockaddr *local_addr, socklen_t local_addrlen,
                  const struct sockaddr *remote_addr, socklen_t remote_addrlen,
                  mlvpn_quic_data_cb data_cb,
                  mlvpn_quic_connected_cb connected_cb);

void mlvpn_quic_destroy(struct mlvpn_quic_ctx *ctx);

int mlvpn_quic_input(struct mlvpn_quic_ctx *ctx, const uint8_t *pkt,
                     size_t pktlen, const struct sockaddr *remote_addr,
                     socklen_t remote_addrlen);

int mlvpn_quic_send(struct mlvpn_quic_ctx *ctx, const uint8_t *data,
                    size_t len);

int mlvpn_quic_flush(struct mlvpn_quic_ctx *ctx);

int mlvpn_quic_handle_expiry(struct mlvpn_quic_ctx *ctx);

ev_tstamp mlvpn_quic_timeout(struct mlvpn_quic_ctx *ctx);

int mlvpn_quic_is_connected(struct mlvpn_quic_ctx *ctx);

int mlvpn_quic_needs_flush(struct mlvpn_quic_ctx *ctx);

#endif
