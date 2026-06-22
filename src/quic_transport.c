/*
 * Userspace QUIC transport for MLVPN using ngtcp2 + GnuTLS.
 * Adapted from ngtcp2 gtlssimpleclient.c (MIT license).
 */
#include "quic_transport.h"
#include "mlvpn.h"
#include "log.h"
#include "crypto.h"

#include <errno.h>
#include <time.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>

#define MLVPN_QUIC_ALPN "\x05mlvpn"
#define MLVPN_QUIC_STREAM_DATA 0

/* quic_send_packet / mlvpn_quic_flush return codes */
#define QUIC_OK       0
#define QUIC_BLOCKED  1
#define QUIC_ERROR   -1

struct mlvpn_quic_ctx {
    struct mlvpn_tunnel_s *tun;
    mlvpn_quic_data_cb data_cb;
    mlvpn_quic_connected_cb connected_cb;
    int server_mode;
    int connected;
    int blocked;
    int fd;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;
    ngtcp2_crypto_conn_ref conn_ref;
    gnutls_certificate_credentials_t cred;
    gnutls_session_t session;
    ngtcp2_conn *conn;
    int64_t stream_id;
    uint8_t *pending;
    size_t pending_len;
    size_t pending_cap;
    uint8_t *outbound;
    size_t outbound_len;
    size_t outbound_cap;
    uint8_t udp_out[MLVPN_QUIC_UDP_PAYLOAD];
    size_t udp_out_len;
};

static uint64_t
quic_timestamp(void)
{
    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
        return 0;
    }
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static void
quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    if (gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen) != 0) {
        memset(dest, 0, destlen);
    }
}

static int
quic_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                              size_t cidlen, void *user_data)
{
    (void)conn;
    (void)user_data;

    if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;
    if (token != NULL &&
        gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static int
quic_open_stream(struct mlvpn_quic_ctx *ctx)
{
    int rv;
    int64_t stream_id;

    if (ctx->stream_id >= 0) {
        return 0;
    }

    rv = ngtcp2_conn_open_bidi_stream(ctx->conn, &stream_id, NULL);
    if (rv != 0) {
        return -1;
    }
    ctx->stream_id = stream_id;
    return 0;
}

static int
quic_extend_max_local_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams,
                                     void *user_data)
{
    struct mlvpn_quic_ctx *ctx = user_data;
    (void)conn;
    (void)max_streams;
    return quic_open_stream(ctx);
}

static int
quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
    struct mlvpn_quic_ctx *ctx = user_data;
    (void)conn;

    quic_open_stream(ctx);
    ctx->connected = 1;
    if (ctx->connected_cb != NULL) {
        ctx->connected_cb(ctx->tun);
    }
    return 0;
}

static int
quic_copy_addr(struct sockaddr_storage *dest, socklen_t *destlen,
               const struct sockaddr *src, socklen_t srclen)
{
    if (src == NULL || srclen == 0) {
        return 0;
    }
    if (srclen > sizeof(*dest)) {
        return -1;
    }
    memcpy(dest, src, srclen);
    *destlen = srclen;
    return 0;
}

static int
quic_buf_append(uint8_t **buf, size_t *len, size_t *cap,
                const uint8_t *data, size_t datalen)
{
    size_t needed;
    uint8_t *newbuf;

    if (datalen == 0) {
        return 0;
    }

    needed = *len + datalen;
    if (needed > *cap) {
        size_t newcap = *cap ? *cap : 4096;

        while (newcap < needed) {
            newcap *= 2;
        }
        newbuf = realloc(*buf, newcap);
        if (newbuf == NULL) {
            return -1;
        }
        *buf = newbuf;
        *cap = newcap;
    }
    memcpy(*buf + *len, data, datalen);
    *len += datalen;
    return 0;
}

static int
quic_pending_append(struct mlvpn_quic_ctx *ctx, const uint8_t *data,
                    size_t datalen)
{
    return quic_buf_append(&ctx->pending, &ctx->pending_len, &ctx->pending_cap,
                           data, datalen);
}

static int
quic_outbound_append(struct mlvpn_quic_ctx *ctx, const uint8_t *data,
                     size_t datalen)
{
    return quic_buf_append(&ctx->outbound, &ctx->outbound_len,
                           &ctx->outbound_cap, data, datalen);
}

static void
quic_process_pending(struct mlvpn_quic_ctx *ctx)
{
    size_t off = 0;
    uint16_t plen;

    while (off + 2 <= ctx->pending_len) {
        plen = (uint16_t)((ctx->pending[off] << 8) | ctx->pending[off + 1]);
        off += 2;
        if (off + plen > ctx->pending_len) {
            off -= 2;
            break;
        }
        if (ctx->data_cb != NULL) {
            ctx->data_cb(ctx->tun, ctx->pending + off, plen);
        }
        off += plen;
    }

    if (off > 0) {
        memmove(ctx->pending, ctx->pending + off, ctx->pending_len - off);
        ctx->pending_len -= off;
    }
}

static int
quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                         uint64_t offset, const uint8_t *data, size_t datalen,
                         void *user_data, void *stream_user_data)
{
    struct mlvpn_quic_ctx *ctx = user_data;
    (void)conn;
    (void)flags;
    (void)stream_id;
    (void)offset;
    (void)stream_user_data;

    if (quic_pending_append(ctx, data, datalen) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    quic_process_pending(ctx);
    return 0;
}

static ngtcp2_conn *
quic_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
    struct mlvpn_quic_ctx *ctx = conn_ref->user_data;
    return ctx->conn;
}

static int
quic_tls_seed(unsigned char seed[32])
{
    static const unsigned char label[] = "mlvpn-quic-tls-v1";
    unsigned char key[crypto_secretbox_KEYBYTES];

    if (crypto_get_key(key, sizeof(key)) != 0) {
        return -1;
    }
    return crypto_generichash(seed, 32, key, sizeof(key), label, sizeof(label) - 1);
}

static int
quic_generate_password_cert(gnutls_x509_crt_t *cert,
                            gnutls_x509_privkey_t *key)
{
    unsigned char seed[32];
    gnutls_datum_t k;

    if (quic_tls_seed(seed) != 0) {
        return -1;
    }

    gnutls_x509_privkey_init(key);
    gnutls_x509_crt_init(cert);

    k.data = seed;
    k.size = sizeof(seed);
    if (gnutls_x509_privkey_import_ecc_raw(*key, GNUTLS_ECC_CURVE_SECP256R1,
                                           NULL, NULL, &k) != 0) {
        gnutls_x509_privkey_deinit(*key);
        gnutls_x509_crt_deinit(*cert);
        return -1;
    }

    if (gnutls_x509_crt_set_key(*cert, *key) != 0 ||
        gnutls_x509_crt_set_version(*cert, 3) != 0 ||
        gnutls_x509_crt_set_activation_time(*cert, 0) != 0 ||
        gnutls_x509_crt_set_expiration_time(*cert, 2147483647) != 0 ||
        gnutls_x509_crt_set_dn(*cert, "cn=mlvpn", NULL) != 0 ||
        gnutls_x509_crt_sign2(*cert, *cert, *key, GNUTLS_DIG_SHA256, 0) != 0) {
        gnutls_x509_privkey_deinit(*key);
        gnutls_x509_crt_deinit(*cert);
        return -1;
    }
    return 0;
}

static int
quic_verify_cert_cb(gnutls_session_t session)
{
    unsigned int list_size;
    const gnutls_datum_t *peers;
    gnutls_x509_crt_t peer_cert, expected_cert;
    gnutls_x509_privkey_t expected_key;
    unsigned char peer_fp[32], expected_fp[32];
    size_t peer_fp_len = sizeof(peer_fp);
    size_t expected_fp_len = sizeof(expected_fp);
    int ret = -1;

    peers = gnutls_certificate_get_peers(session, &list_size);
    if (peers == NULL || list_size == 0) {
        return -1;
    }

    gnutls_x509_crt_init(&peer_cert);
    if (gnutls_x509_crt_import(peer_cert, &peers[0], GNUTLS_X509_FMT_DER) != 0) {
        goto done;
    }

    if (quic_generate_password_cert(&expected_cert, &expected_key) != 0) {
        goto done;
    }

    if (gnutls_x509_crt_get_fingerprint(peer_cert, GNUTLS_DIG_SHA256,
                                        peer_fp, &peer_fp_len) != 0 ||
        gnutls_x509_crt_get_fingerprint(expected_cert, GNUTLS_DIG_SHA256,
                                        expected_fp, &expected_fp_len) != 0) {
        gnutls_x509_privkey_deinit(expected_key);
        gnutls_x509_crt_deinit(expected_cert);
        goto done;
    }

    if (peer_fp_len == expected_fp_len &&
        sodium_memcmp(peer_fp, expected_fp, peer_fp_len) == 0) {
        ret = 0;
    }

    gnutls_x509_privkey_deinit(expected_key);
    gnutls_x509_crt_deinit(expected_cert);

done:
    gnutls_x509_crt_deinit(peer_cert);
    return ret;
}

static int
quic_gnutls_init(struct mlvpn_quic_ctx *ctx)
{
    static int gnutls_ready = 0;
    static const char priority[] =
        "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
        "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
        "+GROUP-SECP384R1:+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";
    static const gnutls_datum_t alpn = {
        (uint8_t *)MLVPN_QUIC_ALPN, sizeof(MLVPN_QUIC_ALPN) - 1
    };
    int rv;

    if (!gnutls_ready) {
        if (gnutls_global_init() != 0) {
            return -1;
        }
        gnutls_ready = 1;
    }

    rv = gnutls_certificate_allocate_credentials(&ctx->cred);
    if (rv != 0) {
        return -1;
    }

    if (ctx->server_mode) {
        gnutls_x509_privkey_t key;
        gnutls_x509_crt_t cert;

        if (quic_generate_password_cert(&cert, &key) != 0) {
            return -1;
        }
        gnutls_certificate_set_x509_key(ctx->cred, &cert, 1, key);
        gnutls_x509_crt_deinit(cert);
        gnutls_x509_privkey_deinit(key);

        rv = gnutls_init(&ctx->session, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA |
                         GNUTLS_NO_END_OF_EARLY_DATA);
        if (rv != 0) {
            return -1;
        }
        if (ngtcp2_crypto_gnutls_configure_server_session(ctx->session) != 0) {
            return -1;
        }
    } else {
        rv = gnutls_init(&ctx->session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |
                         GNUTLS_NO_END_OF_EARLY_DATA);
        if (rv != 0) {
            return -1;
        }
        if (ngtcp2_crypto_gnutls_configure_client_session(ctx->session) != 0) {
            return -1;
        }
        gnutls_session_set_verify_function(ctx->session, quic_verify_cert_cb);
    }

    rv = gnutls_priority_set_direct(ctx->session, priority, NULL);
    if (rv != 0) {
        return -1;
    }

    ctx->conn_ref.get_conn = quic_get_conn;
    ctx->conn_ref.user_data = ctx;
    gnutls_session_set_ptr(ctx->session, &ctx->conn_ref);
    gnutls_credentials_set(ctx->session, GNUTLS_CRD_CERTIFICATE, ctx->cred);
    gnutls_alpn_set_protocols(ctx->session, &alpn, 1, GNUTLS_ALPN_MANDATORY);

    return 0;
}

static int
quic_conn_init(struct mlvpn_quic_ctx *ctx)
{
    ngtcp2_callbacks callbacks = {
        .client_initial = ctx->server_mode ? NULL : ngtcp2_crypto_client_initial_cb,
        .recv_client_initial = ctx->server_mode ? ngtcp2_crypto_recv_client_initial_cb : NULL,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .handshake_completed = quic_handshake_completed_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_stream_data = quic_recv_stream_data_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb,
        .extend_max_local_streams_bidi = quic_extend_max_local_streams_bidi,
        .rand = quic_rand_cb,
        .get_new_connection_id = quic_get_new_connection_id_cb,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    };
    ngtcp2_path path;
    ngtcp2_cid dcid, scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    int rv;

    path.local.addr = (struct sockaddr *)&ctx->local_addr;
    path.local.addrlen = ctx->local_addrlen;
    path.remote.addr = (struct sockaddr *)&ctx->remote_addr;
    path.remote.addrlen = ctx->remote_addrlen;
    path.user_data = NULL;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_timestamp();
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = 1;
    params.initial_max_stream_data_bidi_local = 1024 * 1024;
    params.initial_max_stream_data_bidi_remote = 1024 * 1024;
    params.initial_max_data = 4 * 1024 * 1024;

    scid.datalen = 8;
    if (gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen) != 0) {
        return -1;
    }

    if (ctx->server_mode) {
        dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
        if (gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen) != 0) {
            return -1;
        }
        rv = ngtcp2_conn_server_new(&ctx->conn, &scid, &dcid, &path,
                                    NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                    &params, NULL, ctx);
    } else {
        dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
        if (gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen) != 0) {
            return -1;
        }
        rv = ngtcp2_conn_client_new(&ctx->conn, &dcid, &scid, &path,
                                    NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                    &params, NULL, ctx);
    }

    if (rv != 0) {
        log_warnx("quic", "%s ngtcp2_conn_%s_new failed: %s",
                  ctx->tun->name, ctx->server_mode ? "server" : "client",
                  ngtcp2_strerror(rv));
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->session);
    ctx->stream_id = -1;
    return 0;
}

static int
quic_send_udp(struct mlvpn_quic_ctx *ctx, const uint8_t *data, size_t datalen)
{
    struct iovec iov = {(uint8_t *)data, datalen};
    struct msghdr msg = {0};
    ssize_t nwrite;

    if (datalen > MLVPN_QUIC_UDP_PAYLOAD) {
        return QUIC_ERROR;
    }

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (!ctx->server_mode) {
        msg.msg_name = (void *)&ctx->remote_addr;
        msg.msg_namelen = ctx->remote_addrlen;
    }

    do {
        nwrite = sendmsg(ctx->fd, &msg, 0);
    } while (nwrite == -1 && errno == EINTR);

    if (nwrite == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            memcpy(ctx->udp_out, data, datalen);
            ctx->udp_out_len = datalen;
            ctx->blocked = 1;
            return QUIC_BLOCKED;
        }
        log_warn("quic", "%s sendmsg failed", ctx->tun->name);
        return QUIC_ERROR;
    }
    return QUIC_OK;
}

static int
quic_send_udp_pending(struct mlvpn_quic_ctx *ctx)
{
    int ret;

    if (ctx->udp_out_len == 0) {
        ctx->blocked = 0;
        return QUIC_OK;
    }

    ret = quic_send_udp(ctx, ctx->udp_out, ctx->udp_out_len);
    if (ret == QUIC_OK) {
        ctx->udp_out_len = 0;
        ctx->blocked = 0;
    }
    return ret;
}

static int
quic_drain_outbound(struct mlvpn_quic_ctx *ctx)
{
    uint8_t buf[MLVPN_QUIC_UDP_PAYLOAD];
    ngtcp2_vec datav;
    ngtcp2_ssize nwrite, wdatalen;
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;
    int ret;

    if (ctx->stream_id < 0 && quic_open_stream(ctx) != 0) {
        return QUIC_ERROR;
    }

    while (ctx->outbound_len > 0) {
        ngtcp2_path_storage_zero(&ps);
        datav.base = ctx->outbound;
        datav.len = ctx->outbound_len;

        nwrite = ngtcp2_conn_writev_stream(ctx->conn, &ps.path, &pi, buf,
                                           sizeof(buf), &wdatalen,
                                           NGTCP2_WRITE_STREAM_FLAG_NONE,
                                           ctx->stream_id, &datav, 1,
                                           quic_timestamp());
        if (nwrite < 0 && nwrite != NGTCP2_ERR_WRITE_MORE) {
            log_warnx("quic", "%s writev_stream: %s",
                      ctx->tun->name, ngtcp2_strerror((int)nwrite));
            return QUIC_ERROR;
        }
        if (wdatalen > 0) {
            memmove(ctx->outbound, ctx->outbound + wdatalen,
                    ctx->outbound_len - wdatalen);
            ctx->outbound_len -= wdatalen;
        }
        if (nwrite > 0) {
            ret = quic_send_udp(ctx, buf, (size_t)nwrite);
            if (ret != QUIC_OK) {
                return ret;
            }
        }
        if (nwrite == 0 && wdatalen == 0) {
            break;
        }
    }
    return QUIC_OK;
}

static int
quic_write_packets(struct mlvpn_quic_ctx *ctx)
{
    uint8_t buf[MLVPN_QUIC_UDP_PAYLOAD];
    ngtcp2_ssize nwrite;
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;
    int ret;

    ngtcp2_path_storage_zero(&ps);
    for (;;) {
        nwrite = ngtcp2_conn_write_pkt(ctx->conn, &ps.path, &pi, buf,
                                       sizeof(buf), quic_timestamp());
        if (nwrite == 0) {
            break;
        }
        if (nwrite < 0) {
            log_warnx("quic", "%s write_pkt: %s",
                      ctx->tun->name, ngtcp2_strerror((int)nwrite));
            return QUIC_ERROR;
        }
        ret = quic_send_udp(ctx, buf, (size_t)nwrite);
        if (ret != QUIC_OK) {
            return ret;
        }
    }
    return QUIC_OK;
}

struct mlvpn_quic_ctx *
mlvpn_quic_create(struct mlvpn_tunnel_s *tun, int server_mode, int fd,
                  const struct sockaddr *local_addr, socklen_t local_addrlen,
                  const struct sockaddr *remote_addr, socklen_t remote_addrlen,
                  mlvpn_quic_data_cb data_cb,
                  mlvpn_quic_connected_cb connected_cb)
{
    struct mlvpn_quic_ctx *ctx;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->tun = tun;
    ctx->server_mode = server_mode;
    ctx->fd = fd;
    ctx->data_cb = data_cb;
    ctx->connected_cb = connected_cb;
    ctx->stream_id = -1;

    if (quic_copy_addr(&ctx->local_addr, &ctx->local_addrlen,
                       local_addr, local_addrlen) != 0) {
        log_warnx("quic", "%s invalid local address length", tun->name);
        goto fail;
    }
    if (quic_copy_addr(&ctx->remote_addr, &ctx->remote_addrlen,
                       remote_addr, remote_addrlen) != 0) {
        log_warnx("quic", "%s invalid remote address length", tun->name);
        goto fail;
    }

    if (quic_gnutls_init(ctx) != 0) {
        log_warnx("quic", "%s TLS init failed", tun->name);
        goto fail;
    }

    if (quic_conn_init(ctx) != 0) {
        goto fail;
    }

    if (mlvpn_quic_flush(ctx) < 0) {
        goto fail;
    }

    return ctx;

fail:
    mlvpn_quic_destroy(ctx);
    return NULL;
}

void
mlvpn_quic_destroy(struct mlvpn_quic_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->conn != NULL) {
        ngtcp2_conn_del(ctx->conn);
    }
    if (ctx->session != NULL) {
        gnutls_deinit(ctx->session);
    }
    if (ctx->cred != NULL) {
        gnutls_certificate_free_credentials(ctx->cred);
    }
    free(ctx->pending);
    free(ctx->outbound);
    free(ctx);
}

int
mlvpn_quic_input(struct mlvpn_quic_ctx *ctx, const uint8_t *pkt, size_t pktlen,
                 const struct sockaddr *remote_addr, socklen_t remote_addrlen)
{
    ngtcp2_path path;
    ngtcp2_pkt_info pi = {0};
    int rv;

    if (ctx == NULL || ctx->conn == NULL) {
        return -1;
    }

    if (remote_addr != NULL && remote_addrlen > 0) {
        if (quic_copy_addr(&ctx->remote_addr, &ctx->remote_addrlen,
                           remote_addr, remote_addrlen) != 0) {
            log_warnx("quic", "%s invalid peer address length", ctx->tun->name);
            return QUIC_ERROR;
        }
    }

    path.local.addr = (struct sockaddr *)&ctx->local_addr;
    path.local.addrlen = ctx->local_addrlen;
    path.remote.addr = (struct sockaddr *)&ctx->remote_addr;
    path.remote.addrlen = ctx->remote_addrlen;
    path.user_data = NULL;

    rv = ngtcp2_conn_read_pkt(ctx->conn, &path, &pi, pkt, pktlen,
                              quic_timestamp());
    if (rv != 0) {
        log_warnx("quic", "%s read_pkt: %s", ctx->tun->name, ngtcp2_strerror(rv));
        return QUIC_ERROR;
    }

    return mlvpn_quic_flush(ctx);
}

int
mlvpn_quic_send(struct mlvpn_quic_ctx *ctx, const uint8_t *data, size_t len)
{
    uint8_t frame[DEFAULT_MTU + 2];
    int ret;

    if (ctx == NULL || ctx->conn == NULL || !ctx->connected) {
        return QUIC_ERROR;
    }
    if (len > DEFAULT_MTU) {
        return QUIC_ERROR;
    }

    frame[0] = (uint8_t)(len >> 8);
    frame[1] = (uint8_t)(len & 0xff);
    memcpy(frame + 2, data, len);

    if (quic_outbound_append(ctx, frame, len + 2) != 0) {
        return QUIC_ERROR;
    }

    ret = mlvpn_quic_flush(ctx);
    if (ret == QUIC_ERROR) {
        return QUIC_ERROR;
    }
    return (int)len;
}

int
mlvpn_quic_flush(struct mlvpn_quic_ctx *ctx)
{
    int ret;

    if (ctx == NULL || ctx->conn == NULL) {
        return QUIC_ERROR;
    }

    ret = quic_send_udp_pending(ctx);
    if (ret != QUIC_OK) {
        return ret;
    }

    ret = quic_drain_outbound(ctx);
    if (ret != QUIC_OK) {
        return ret;
    }

    ret = quic_write_packets(ctx);
    if (ret != QUIC_OK) {
        return ret;
    }

    /* Stream data may have generated more QUIC packets */
    ret = quic_write_packets(ctx);
    if (ret != QUIC_OK) {
        return ret;
    }

    if (ctx->outbound_len > 0 || ctx->udp_out_len > 0) {
        ctx->blocked = 1;
        return QUIC_BLOCKED;
    }
    ctx->blocked = 0;
    return QUIC_OK;
}

int
mlvpn_quic_handle_expiry(struct mlvpn_quic_ctx *ctx)
{
    int rv;

    if (ctx == NULL || ctx->conn == NULL) {
        return QUIC_ERROR;
    }
    rv = ngtcp2_conn_handle_expiry(ctx->conn, quic_timestamp());
    if (rv != 0) {
        return QUIC_ERROR;
    }
    return mlvpn_quic_flush(ctx);
}

ev_tstamp
mlvpn_quic_timeout(struct mlvpn_quic_ctx *ctx)
{
    ngtcp2_tstamp expiry, now;

    if (ctx == NULL || ctx->conn == NULL) {
        return 1.0;
    }
    expiry = ngtcp2_conn_get_expiry(ctx->conn);
    now = quic_timestamp();
    if (expiry <= now) {
        return 0.001;
    }
    return (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;
}

int
mlvpn_quic_is_connected(struct mlvpn_quic_ctx *ctx)
{
    return ctx != NULL && ctx->connected;
}

int
mlvpn_quic_needs_flush(struct mlvpn_quic_ctx *ctx)
{
    return ctx != NULL &&
        (ctx->blocked || ctx->udp_out_len > 0 || ctx->outbound_len > 0);
}
