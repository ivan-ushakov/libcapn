#include "apn_http2_request.h"
#include "apn.h"
#include "apn_paload_private.h"
#include "apn_strings.h"
#include "apn_memory.h"

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
    memset(request, 0, sizeof(apn_http2_request_t));

    request->path = apn_printf("/3/device/%s", token);
    if (!request->path) {
        apn_http2_request_free(request);
        return NULL;
    }

    request->token = apn_strndup(token, strlen(token));
    if (!request->token) {
        apn_http2_request_free(request);
        return NULL;
    }

    request->body = apn_create_json_document_from_payload(payload);
    if (!request->body) {
        apn_http2_request_free(request);
        return NULL;
    }

    request->body_size = strlen(request->body);
    if (request->body_size > APN_PAYLOAD_MAX_SIZE) {
        apn_http2_request_free(request);
        errno = APN_ERR_INVALID_PAYLOAD_SIZE;
        return NULL;
    }

    request->response = malloc(1);
    request->response_size = 0;

    return request;
}

void apn_http2_request_free(apn_http2_request_t *request) {
    apn_mem_free(request->path);
    apn_mem_free(request->token);
    apn_mem_free(request->body);
    apn_mem_free(request->response);
    free(request);
}
