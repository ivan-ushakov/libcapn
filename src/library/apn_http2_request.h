#ifndef __APN_HTTP2_REQUEST_H__
#define __APN_HTTP2_REQUEST_H__

#include "apn_platform.h"
#include "apn_payload.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct __apn_http2_request_t {
    char *host;
    uint16_t port;
    char *path;
    char *token;
    char *body;
    size_t body_size;
    size_t body_send_cursor;
    char *response;
    size_t response_size;
    char *apns_id;
    int32_t status;
} apn_http2_request_t;

__apn_export__ apn_http2_request_t *apn_http2_request_create(const apn_payload_t *const payload, const char *token)
        __apn_attribute_warn_unused_result__
        __apn_attribute_nonnull__((1,2));

__apn_export__ void apn_http2_request_free(apn_http2_request_t *request)
        __apn_attribute_nonnull__((1));

#ifdef	__cplusplus
}
#endif

#endif
