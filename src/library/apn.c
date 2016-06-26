/*
 * Copyright (c) 2013-2015 Anton Dobkin <anton.dobkin@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "apn_platform.h"

#include <errno.h>
#include <assert.h>

#include "apn_strings.h"
#include "apn_tokens.h"
#include "apn_version.h"
#include "apn_paload_private.h"
#include "apn_private.h"
#include "apn_array_private.h"
#include "apn_memory.h"
#include "apn_strerror.h"
#include "apn_log.h"
#include "apn_ssl.h"
#include "apn_http2.h"
#include "apn_http2_request.h"

#ifdef APN_HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef APN_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef APN_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef APN_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef APN_HAVE_NETDB_H
#include <netdb.h>
#endif

typedef enum __apn_apple_errors {
    APN_APNS_ERR_PROCESSING_ERROR = 1,
    APN_APNS_ERR_MISSING_DEVICE_TOKEN,
    APN_APNS_ERR_MISSING_TOPIC,
    APN_APNS_ERR_MISSING_PAYLOAD,
    APN_APNS_ERR_INVALID_TOKEN_SIZE,
    APN_APNS_ERR_INVALID_TOPIC_SIZE,
    APN_APNS_ERR_INVALID_PAYLOAD_SIZE,
    APN_APNS_ERR_INVALID_TOKEN,
    APN_APNS_ERR_SERVICE_SHUTDOWN = 10,
    APN_APNS_ERR_NONE = 255
} apn_apple_errors;

struct __apn_apple_server {
    char *host;
    uint16_t port;
};

static struct __apn_apple_server __apn_apple_servers[2] = {
        {"api.development.push.apple.com", 443},
        {"api.push.apple.com", 443}
};

static apn_return __apn_connect(apn_ctx_t *const ctx, struct __apn_apple_server server);
static void __apn_parse_apns_error(char *apns_error, uint8_t *apns_error_code, uint32_t *id);
static int __apn_convert_apple_error(uint8_t apple_error_code);
static void __apn_invalid_token_dtor(char *const token);

apn_return apn_library_init() {
    static uint8_t library_initialized = 0;
    if (!library_initialized) {
        apn_ssl_init();
        library_initialized = 1;
#ifdef _WIN32
        WSADATA wsa_data;
        if(WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            errno = APN_ERR_FAILED_INIT;
            return APN_ERROR;
        }
#endif
    }
    return APN_SUCCESS;
}

void apn_library_free() {
    apn_ssl_free();
#ifdef _WIN32
    WSACleanup();
#endif
}

apn_ctx_t *apn_init() {
    apn_ctx_t *ctx = NULL;
    if (APN_ERROR == apn_library_init()) {
        return NULL;
    }
    ctx = malloc(sizeof(apn_ctx_t));
    if (!ctx) {
        errno = ENOMEM;
        return NULL;
    }
    ctx->sock = -1;
    ctx->ssl = NULL;
    ctx->callbacks = NULL;
    ctx->session = NULL;
    ctx->authority = NULL;
    ctx->certificate_file = NULL;
    ctx->private_key_file = NULL;
    ctx->pkcs12_file = NULL;
    ctx->pkcs12_pass = NULL;
    ctx->private_key_pass = NULL;
    ctx->mode = APN_MODE_PRODUCTION;
    ctx->log_callback = NULL;
    ctx->log_level = APN_LOG_LEVEL_ERROR;
    ctx->invalid_token_callback = NULL;
    return ctx;
}

void apn_free(apn_ctx_t *ctx) {
    if (ctx) {
        apn_close(ctx);
        apn_http2_free(ctx);
        apn_mem_free(ctx->authority);
        apn_mem_free(ctx->certificate_file);
        apn_mem_free(ctx->private_key_file);
        apn_mem_free(ctx->private_key_pass);
        apn_mem_free(ctx->pkcs12_file);
        apn_mem_free(ctx->pkcs12_pass);
        free(ctx);
    }
}

void apn_close(apn_ctx_t *const ctx) {
    assert(ctx);
    if(-1 == ctx->sock) {
        return;
    }
    apn_log(ctx, APN_LOG_LEVEL_INFO, "Connection closing...");
    apn_ssl_close(ctx);
    APN_CLOSE_SOCKET(ctx->sock);
    ctx->sock = -1;
    apn_log(ctx, APN_LOG_LEVEL_INFO, "Connection closed");
}

apn_return apn_set_certificate(apn_ctx_t *const ctx, const char *const cert, const char *const key,
                               const char *const pass) {
    assert(ctx);

    apn_strfree(&ctx->certificate_file);
    apn_strfree(&ctx->private_key_file);
    apn_strfree(&ctx->private_key_pass);

    if (cert && strlen(cert) > 0) {
        if (NULL == (ctx->certificate_file = apn_strndup(cert, strlen(cert)))) {
            return APN_ERROR;
        }
        if (key && strlen(key) > 0) {
            if (NULL == (ctx->private_key_file = apn_strndup(key, strlen(key)))) {
                return APN_ERROR;
            }
            if (pass && strlen(pass) > 0) {
                if (NULL == (ctx->private_key_pass = apn_strndup(pass, strlen(pass)))) {
                    return APN_ERROR;
                }
            }
        }
    }
    return APN_SUCCESS;
}

apn_return apn_set_pkcs12_file(apn_ctx_t *const ctx, const char *const pkcs12_file, const char *const pass) {
    assert(ctx);

    apn_strfree(&ctx->pkcs12_file);
    apn_strfree(&ctx->pkcs12_pass);

    if (pkcs12_file && strlen(pkcs12_file) > 0) {
        if (NULL == (ctx->pkcs12_file = apn_strndup(pkcs12_file, strlen(pkcs12_file)))) {
            return APN_ERROR;
        }
        assert(pass && strlen(pass) > 0);
        if (NULL == (ctx->pkcs12_pass = apn_strndup(pass, strlen(pass)))) {
            return APN_ERROR;
        }
    }
    return APN_SUCCESS;
}

void apn_set_mode(apn_ctx_t *const ctx, apn_connection_mode mode) {
    assert(ctx);
    if (mode == APN_MODE_SANDBOX) {
        ctx->mode = APN_MODE_SANDBOX;
    } else {
        ctx->mode = APN_MODE_PRODUCTION;
    }
}

void apn_set_behavior(apn_ctx_t * const ctx, uint32_t options) {
    assert(ctx);
    ctx->options = options;
}

void apn_set_log_level(apn_ctx_t *const ctx, uint16_t level) {
    assert(ctx);
    ctx->log_level = level;
}

void apn_set_log_callback(apn_ctx_t *const ctx, log_callback funct) {
    assert(ctx);
    ctx->log_callback = funct;
}

void apn_set_invalid_token_callback(apn_ctx_t *const ctx, invalid_token_callback funct) {
    assert(ctx);
    ctx->invalid_token_callback = funct;
}

apn_connection_mode apn_mode(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->mode;
}

uint16_t apn_log_level(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->log_level;
}

uint32_t apn_behavior(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->options;
}

const char *apn_certificate(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->certificate_file;
}

const char *apn_private_key(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->private_key_file;
}

const char *apn_private_key_pass(const apn_ctx_t *const ctx) {
    assert(ctx);
    return ctx->private_key_pass;
}

apn_return apn_connect(apn_ctx_t *const ctx) {
    struct __apn_apple_server server;
    if (ctx->mode == APN_MODE_SANDBOX) {
        server = __apn_apple_servers[0];
    } else {
        server = __apn_apple_servers[1];
    }

    if (!ctx->authority) {
        ctx->authority = apn_printf("%s:%d", server.host, server.port);
        if (!ctx->authority) {
            return APN_ERROR;
        }
    }

    return __apn_connect(ctx, server);
}

#define __APN_CHECK_CONNECTION(__ctx) \
    if (!__ctx->ssl) {\
        apn_log(__ctx, APN_LOG_LEVEL_ERROR, "Connection was not opened");\
        errno = APN_ERR_NOT_CONNECTED;\
        return APN_ERROR;\
    }


apn_return apn_send(apn_ctx_t *const ctx, const apn_payload_t *payload, apn_array_t *tokens) {
    assert(ctx);
    assert(payload);
    assert(tokens);
    assert(apn_array_count(tokens) > 0);

    __APN_CHECK_CONNECTION(ctx)

    for (uint32_t i = 0; i < apn_array_count(tokens); i++) {
        const char *token = (const char *)apn_array_item_at_index(tokens, i);
        apn_http2_request_t *request = apn_http2_request_create(payload, token);
        if (NULL == request) {
            return APN_ERROR;
        }

        if (APN_ERROR == apn_http2_send_request(ctx, request)) {
            return APN_ERROR;
        }
    }

    return APN_SUCCESS;
}

uint32_t apn_version() {
    return APN_VERSION_NUM;
}

const char *apn_version_string() {
    return APN_VERSION_STRING;
}

char *apn_error_string(int errnum) {
    char error[250] = {0};
    switch (errnum) {
        case APN_ERR_FAILED_INIT:
            apn_snprintf(error, sizeof(error) - 1, "unable to initialize library");
            break;
        case APN_ERR_NOT_CONNECTED:
            apn_snprintf(error, sizeof(error) - 1, "no opened connection to Apple Push Notification Service");
            break;
        case APN_ERR_NOT_CONNECTED_FEEDBACK:
            apn_snprintf(error, sizeof(error) - 1, "no opened connection to Apple Feedback Service");
            break;
        case APN_ERR_CONNECTION_CLOSED:
            apn_snprintf(error, sizeof(error) - 1, "connection was closed");
            break;
        case APN_ERR_NETWORK_TIMEDOUT:
            apn_snprintf(error, sizeof(error) - 1, "connection timed out");
            break;
        case APN_ERR_NETWORK_UNREACHABLE:
            apn_snprintf(error, sizeof(error) - 1, "network unreachable");
            break;
        case APN_ERR_TOKEN_INVALID:
            apn_snprintf(error, sizeof(error) - 1, "invalid device token");
            break;
        case APN_ERR_TOKEN_TOO_MANY:
            apn_snprintf(error, sizeof(error) - 1, "too many device tokens");
            break;
        case APN_ERR_CERTIFICATE_IS_NOT_SET:
            apn_snprintf(error, sizeof(error) - 1, "certificate is not set");
            break;
        case APN_ERR_PRIVATE_KEY_IS_NOT_SET:
            apn_snprintf(error, sizeof(error) - 1, "private key is not set");
            break;
        case APN_ERR_UNABLE_TO_USE_SPECIFIED_CERTIFICATE:
            apn_snprintf(error, sizeof(error) - 1, "unable to use specified certificate");
            break;
        case APN_ERR_UNABLE_TO_USE_SPECIFIED_PRIVATE_KEY:
            apn_snprintf(error, sizeof(error) - 1, "unable to use specified private key");
            break;
        case APN_ERR_UNABLE_TO_USE_SPECIFIED_PKCS12:
            apn_snprintf(error, sizeof(error) - 1, "unable to use specified PKCS12 file");
            break;
        case APN_ERR_UNABLE_TO_ESTABLISH_CONNECTION:
            apn_snprintf(error, sizeof(error) - 1, "unable to establish connection");
            break;
        case APN_ERR_UNABLE_TO_ESTABLISH_SSL_CONNECTION:
            apn_snprintf(error, sizeof(error) - 1, "unable to establish ssl connection");
            break;
        case APN_ERR_SSL_WRITE_FAILED:
            apn_snprintf(error, sizeof(error) - 1, "SSL_write failed");
            break;
        case APN_ERR_SSL_READ_FAILED:
            apn_snprintf(error, sizeof(error) - 1, "SSL_read failed");
            break;
        case APN_ERR_INVALID_PAYLOAD_SIZE:
            apn_snprintf(error, sizeof(error) - 1, "invalid notification payload size");
            break;
        case APN_ERR_PAYLOAD_BADGE_INVALID_VALUE:
            apn_snprintf(error, sizeof(error) - 1, "incorrect number to display as the badge on application icon");
            break;
        case APN_ERR_PAYLOAD_CUSTOM_PROPERTY_KEY_IS_ALREADY_USED:
            apn_snprintf(error, sizeof(error) - 1, "specified custom property name is already used");
            break;
        case APN_ERR_PAYLOAD_COULD_NOT_CREATE_JSON_DOCUMENT:
            apn_snprintf(error, sizeof(error) - 1, "could not create json document");
            break;
        case APN_ERR_STRING_CONTAINS_NON_UTF8_CHARACTERS:
            apn_snprintf(error, sizeof(error) - 1, "non-UTF8 symbols detected in a string");
            break;
        case APN_ERR_PROCESSING_ERROR:
            apn_snprintf(error, sizeof(error) - 1, "processing error");
            break;
        case APN_ERR_SERVICE_SHUTDOWN:
            apn_snprintf(error, sizeof(error) - 1, "server closed the connection (service shutdown)");
            break;
        case APN_ERR_PAYLOAD_ALERT_IS_NOT_SET:
            apn_snprintf(error, sizeof(error) - 1,
                         "alert message text or key used to get a localized alert-message string or content-available flag must be set");
            break;
        default:
            apn_strerror(errnum, error, sizeof(error) - 1);
            break;
    }
    return apn_strndup(error, sizeof(error));
}

static apn_return __apn_connect(apn_ctx_t *const ctx, struct __apn_apple_server server) {
    apn_log(ctx, APN_LOG_LEVEL_INFO, "Connecting to %s:%d...", server.host, server.port);

    if (!ctx->pkcs12_file) {
        if (!ctx->certificate_file) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Certificate file not set (errno: %d)", APN_ERR_CERTIFICATE_IS_NOT_SET);
            errno = APN_ERR_CERTIFICATE_IS_NOT_SET;
            return APN_ERROR;
        }
        if (!ctx->private_key_file) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Private key file not set (errno: %d)", APN_ERR_PRIVATE_KEY_IS_NOT_SET);
            errno = APN_ERR_PRIVATE_KEY_IS_NOT_SET;
            return APN_ERROR;
        }
    }

    if (ctx->sock == -1) {
        apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Resolving server hostname...");

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV;

        char str_port[6];
        apn_snprintf(str_port, sizeof(str_port) - 1, "%d", server.port);

        struct addrinfo *addrinfo = NULL;
        if (0 != getaddrinfo(server.host, str_port, &hints, &addrinfo)) {
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to resolve hostname: getaddrinfo() failed");
            errno  = APN_ERR_UNABLE_TO_ESTABLISH_CONNECTION;
            return APN_ERROR;
        }

        apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Creating socket...");

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            char *error = apn_error_string(errno);
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to create socket: socket() failed: %s (errno: %d)", error,
                      errno);
            free(error);
            return APN_ERROR;
        }

#ifndef _WIN32
        int sock_flags = fcntl(ctx->sock, F_GETFL, 0);
        fcntl(ctx->sock, F_SETFL, sock_flags | O_NONBLOCK);
#else
        int sock_flags = 1;
        ioctlsocket(ctx->sock, FIONBIO, (u_long *) &sock_flags);
#endif
        apn_log(ctx, APN_LOG_LEVEL_DEBUG, "Socket successfully created");

        uint8_t connected = 0;
        while (addrinfo) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, (void *) &((struct sockaddr_in *) addrinfo->ai_addr)->sin_addr, ip, sizeof(ip));
            apn_log(ctx, APN_LOG_LEVEL_INFO, "Trying to connect to %s...", ip);
            if (connect(sock, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0) {
                char *error = apn_error_string(errno);
                apn_log(ctx, APN_LOG_LEVEL_ERROR, "Could not to connect to: %s (errno: %d)", error, errno);
                free(error);
            } else {
                connected = 1;
                break;
            }
            addrinfo = addrinfo->ai_next;
        }

        freeaddrinfo(addrinfo);

        if (!connected) {
            errno = APN_ERR_UNABLE_TO_ESTABLISH_CONNECTION;
            apn_log(ctx, APN_LOG_LEVEL_ERROR, "Unable to establish connection");
            apn_close(ctx);
            return APN_ERROR;
        }

        apn_log(ctx, APN_LOG_LEVEL_INFO, "Connection has been established");
        apn_log(ctx, APN_LOG_LEVEL_INFO, "Initializing SSL connection...");
        ctx->sock = sock;

        apn_return r = apn_ssl_connect(ctx);
        if (r != APN_SUCCESS) {
            return r;
        }

        return apn_http2_run_event_loop(ctx);
    }
    return APN_SUCCESS;
}

static void __apn_parse_apns_error(char *apns_error, uint8_t *apns_error_code, uint32_t *id) {
    uint8_t cmd = 0;
    memcpy(&cmd, apns_error, sizeof(uint8_t));
    apns_error += sizeof(uint8_t);
    if (8 == cmd) {
        uint8_t error_code = 0;
        memcpy(&error_code, apns_error, sizeof(uint8_t));
        apns_error += sizeof(uint8_t);
        if (apns_error_code) {
            *apns_error_code = error_code;
        }
        if (APN_APNS_ERR_INVALID_TOKEN == error_code && id) {
            uint32_t token_id = 0;
            memcpy(&token_id, apns_error, sizeof(uint32_t));
            *id = ntohl(token_id);
        }
    }
}

static int __apn_convert_apple_error(uint8_t apple_error_code) {
    if (apple_error_code > 0) {
        switch (apple_error_code) {
            case APN_APNS_ERR_PROCESSING_ERROR:
                return APN_ERR_PROCESSING_ERROR;
            case APN_APNS_ERR_INVALID_PAYLOAD_SIZE:
                return APN_ERR_INVALID_PAYLOAD_SIZE;
            case APN_APNS_ERR_SERVICE_SHUTDOWN:
                return APN_ERR_SERVICE_SHUTDOWN;
            case APN_APNS_ERR_INVALID_TOKEN:
            case APN_APNS_ERR_INVALID_TOKEN_SIZE:
                return APN_ERR_TOKEN_INVALID;
            default:
                return APN_ERR_UNKNOWN;
        }
    }
    return 0;
}

static void __apn_invalid_token_dtor(char *const token) {
    free(token);
}
