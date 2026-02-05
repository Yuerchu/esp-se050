#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "esp_se050_session_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t esp_se050_session_acquire(const esp_se050_session_cfg_t *cfg);
void esp_se050_session_release(void);

esp_err_t esp_se050_tls_pki_setup(mbedtls_ssl_config *conf,
    mbedtls_x509_crt *cert,
    mbedtls_pk_context *key,
    const void *cfg);

esp_err_t esp_se050_read_object(uint32_t object_id, uint8_t *buf, size_t *len);

esp_err_t esp_se050_make_refkey_p256(uint32_t key_id,
    const uint8_t *pubkey_uncompressed,
    size_t pubkey_len,
    uint8_t *out_der_key,
    size_t *out_der_key_len);

#ifdef __cplusplus
}
#endif
