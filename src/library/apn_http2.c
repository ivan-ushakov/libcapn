#include "apn_http2.h"
#include "apn_private.h"
#include "apn_http2_request.h"
#include "apn_log.h"

#include <inttypes.h>
#include <stdlib.h>

#ifdef APN_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef APN_HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <sys/types.h>

#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

enum { IO_NONE, WANT_READ, WANT_WRITE };

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,   \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_CS(NAME, VALUE)                                                \
  {                                                                            \
    (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),       \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    apn_ctx_t *ctx = (apn_ctx_t *)user_data;
    ctx->want_io = IO_NONE;
    ERR_clear_error();

    int rv = SSL_write(ctx->ssl, data, (int)length);
    if (rv <= 0) {
        int err = SSL_get_error(ctx->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            ctx->want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
            rv = NGHTTP2_ERR_WOULDBLOCK;
        } else {
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return rv;
}

static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) {
    apn_ctx_t *ctx = (apn_ctx_t *)user_data;
    ctx->want_io = IO_NONE;
    ERR_clear_error();

    int rv = SSL_read(ctx->ssl, buf, (int)length);
    if (rv < 0) {
        int err = SSL_get_error(ctx->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            ctx->want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
            rv = NGHTTP2_ERR_WOULDBLOCK;
        } else {
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    } else if (rv == 0) {
        rv = NGHTTP2_ERR_EOF;
    }
    return rv;
}

static int on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    apn_ctx_t *ctx = (apn_ctx_t *)user_data;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "NGHTTP2_HEADERS");
            break;
        case NGHTTP2_RST_STREAM:
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "NGHTTP2_RST_STREAM");
            break;
        case NGHTTP2_GOAWAY:
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "NGHTTP2_GOAWAY");
            break;
        default:
            break;
    }
    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    apn_ctx_t *ctx = (apn_ctx_t *)user_data;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "NGHTTP2_HEADERS");
            break;
        case NGHTTP2_RST_STREAM:
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "NGHTTP2_RST_STREAM");
            break;
        case NGHTTP2_GOAWAY:
            apn_log(ctx, APN_LOG_LEVEL_DEBUG, "NGHTTP2_GOAWAY");
            break;
        default:
            break;
    }
    return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    apn_ctx_t *ctx = (apn_ctx_t *)user_data;
    apn_http2_request_t *req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (req) {
        int rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
        if (rv != 0) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "nghttp2_session_terminate_session: %d", rv);
        }
    }
    return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) {
    apn_ctx_t *ctx = (apn_ctx_t *)user_data;
    apn_http2_request_t *req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (req) {
        apn_log(ctx, APN_LOG_LEVEL_DEBUG, "DATA chunk %lu bytes", (unsigned long int)len);
    }
    return 0;
}

static void setup_callbacks(apn_ctx_t *const ctx) {
    int rv = nghttp2_session_callbacks_new(&ctx->callbacks);
    if (rv != 0) {
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "nghttp2_session_callbacks_new: %d", rv);
        return;
    }

    nghttp2_session_callbacks_set_send_callback(ctx->callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(ctx->callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_frame_send_callback(ctx->callbacks, on_frame_send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(ctx->callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(ctx->callbacks, on_stream_close_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ctx->callbacks, on_data_chunk_recv_callback);
}

static void ctl_poll(struct pollfd *pollfd, apn_ctx_t *const ctx) {
    pollfd->events = 0;
    if (nghttp2_session_want_read(ctx->session) || ctx->want_io == WANT_READ) {
        pollfd->events |= POLLIN;
    }

    if (nghttp2_session_want_write(ctx->session) || ctx->want_io == WANT_WRITE) {
        pollfd->events |= POLLOUT;
    }
}

static void exec_io(apn_ctx_t *const ctx) {
    int rv = nghttp2_session_recv(ctx->session);
    if (rv != 0) {
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "nghttp2_session_recv: %d", rv);
    }

    rv = nghttp2_session_send(ctx->session);
    if (rv != 0) {
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "nghttp2_session_send: %d", rv);
    }
}

void *apn_http2_event_loop(void *data) {
    apn_ctx_t *ctx = (apn_ctx_t *)data;

    nfds_t npollfds = 1;
    struct pollfd pollfds[1];

    pollfds[0].fd = ctx->sock;
    ctl_poll(pollfds, ctx);

    while (nghttp2_session_want_read(ctx->session) || nghttp2_session_want_write(ctx->session)) {
        int nfds = poll(pollfds, npollfds, -1);
        if (nfds == -1) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "poll: %s", strerror(errno));
            break;
        }

        if (pollfds[0].revents & (POLLIN | POLLOUT)) {
            exec_io(ctx);
        }

        if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "connection");
            break;
        }
        ctl_poll(pollfds, ctx);
    }

    return NULL;
}

apn_return apn_http2_init(apn_ctx_t *const ctx) {
    setup_callbacks(ctx);
    int rv = nghttp2_session_client_new(&ctx->session, ctx->callbacks, ctx);
    if (rv != 0) {
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "nghttp2_session_client_new: %d", rv);
        return APN_ERROR;
    }

    nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, NULL, 0);
    return APN_SUCCESS;
}

void apn_http2_free(apn_ctx_t *const ctx) {
    if (ctx->callbacks) {
        nghttp2_session_callbacks_del(ctx->callbacks);
    }

    if (ctx->session) {
        nghttp2_session_del(ctx->session);
    }
}

apn_return apn_http2_run_event_loop(apn_ctx_t *const ctx) {
    if (pthread_create(&ctx->thread, NULL, apn_http2_event_loop, ctx)) {
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "pthread_create");
        return APN_ERROR;
    }
    return APN_SUCCESS;
}

apn_return apn_http2_send_request(apn_ctx_t *const ctx, apn_http2_request_t *const request) {
    const nghttp2_nv nva[] = {
            MAKE_NV(":method", "POST"), MAKE_NV_CS(":path", request->path),
            MAKE_NV(":scheme", "https"), MAKE_NV_CS(":authority", ctx->authority),
            MAKE_NV("accept", "*/*"),
            MAKE_NV("user-agent", "nghttp2/" NGHTTP2_VERSION)};

    int32_t stream_id = nghttp2_submit_request(ctx->session, NULL, nva, sizeof(nva) / sizeof(nva[0]), NULL, request);
    if (stream_id < 0) {
        apn_log(ctx, APN_LOG_LEVEL_ERROR, "nghttp2_submit_request: %d", stream_id);
        apn_http2_request_free(request);
        return APN_ERROR;
    }

    request->stream_id = stream_id;
    apn_log(ctx, APN_LOG_LEVEL_DEBUG, "stream ID: %d", stream_id);

    return APN_SUCCESS;
}
