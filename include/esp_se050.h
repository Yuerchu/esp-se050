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

/**
 * @brief TLS PKI configuration for SE050.
 *
 * Decouples esp-se050 from esp_tls_cfg_t to avoid circular dependency.
 */
typedef struct {
    uint32_t key_id;                               /*!< SE050 object ID for private key */
    uint32_t cert_id;                              /*!< SE050 object ID for certificate (0 = use clientcert_buf) */
    const uint8_t *clientcert_buf;                 /*!< Client certificate buffer (PEM/DER), NULL to read from SE050 */
    size_t clientcert_bytes;                       /*!< Length of clientcert_buf */
    const esp_se050_session_cfg_t *session_cfg;    /*!< SCP03/ECKey session config (NULL for plaintext) */
} esp_se050_tls_cfg_t;

esp_err_t esp_se050_session_acquire(const esp_se050_session_cfg_t *cfg);
void esp_se050_session_release(void);

/**
 * @brief Set up TLS PKI using SE050 hardware key.
 *
 * Acquires SE050 session, loads certificate, constructs reference key,
 * and configures mbedTLS ssl_config for mutual TLS authentication.
 */
esp_err_t esp_se050_tls_pki_setup(mbedtls_ssl_config *conf,
    mbedtls_x509_crt *cert,
    mbedtls_pk_context *key,
    const esp_se050_tls_cfg_t *cfg);

esp_err_t esp_se050_read_object(uint32_t object_id, uint8_t *buf, size_t *len);

esp_err_t esp_se050_make_refkey_p256(uint32_t key_id,
    const uint8_t *pubkey_uncompressed,
    size_t pubkey_len,
    uint8_t *out_der_key,
    size_t *out_der_key_len);

#ifdef __cplusplus
}
#endif
