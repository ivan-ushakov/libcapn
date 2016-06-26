#include "apn_http2_request.h"
#include "apn.h"
#include "apn_paload_private.h"
#include "apn_strings.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <nghttp2/nghttp2.h>

apn_http2_request_t *apn_http2_request_create(const apn_payload_t *const payload, const char *token) {
    apn_http2_request_t *request = malloc(sizeof(apn_http2_request_t));
    if (!request) {
        errno = ENOMEM;
        return NULL;
    }

    request->path = apn_printf("/3/device/%s", token);
    if (!request->path) {
        apn_http2_request_free(request);
        return NULL;
    }

    request->body = apn_create_json_document_from_payload(payload);
    if (!request->body) {
        apn_http2_request_free(request);
        return NULL;
    }

    size_t body_size = strlen(request->body);
    if (body_size > APN_PAYLOAD_MAX_SIZE) {
        apn_http2_request_free(request);
        errno = APN_ERR_INVALID_PAYLOAD_SIZE;
        return NULL;
    }

    return request;
}

void apn_http2_request_free(apn_http2_request_t *request) {
    if (request->path) free(request->path);
    if (request->body) free(request->body);
    free(request);
}
