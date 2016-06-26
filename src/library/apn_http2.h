#ifndef __APN_HTTP2_H__
#define __APN_HTTP2_H__

#include "apn_platform.h"
#include "apn.h"
#include "apn_http2_request.h"

#ifdef	__cplusplus
extern "C" {
#endif

__apn_export__ apn_return apn_http2_init(apn_ctx_t *const ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ void apn_http2_free(apn_ctx_t *const ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_http2_run_event_loop(apn_ctx_t *const ctx)
        __apn_attribute_nonnull__((1));

__apn_export__ apn_return apn_http2_send_request(apn_ctx_t *const ctx, apn_http2_request_t *const request)
        __apn_attribute_nonnull__((1,2));

#ifdef	__cplusplus
}
#endif

#endif
