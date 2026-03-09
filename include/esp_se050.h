#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "esp_se050_session_cfg.h"
#include <sdkconfig.h>

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

/**
 * @brief  Supported EC curves for SE050 reference key generation.
 */
typedef enum {
    ESP_SE050_EC_P256 = 0,    /*!< NIST P-256 (secp256r1), 32-byte scalar, 65-byte uncompressed point */
    ESP_SE050_EC_P384 = 1,    /*!< NIST P-384 (secp384r1), 48-byte scalar, 97-byte uncompressed point */
} esp_se050_ec_curve_t;

esp_err_t esp_se050_session_acquire(const esp_se050_session_cfg_t *cfg);
void esp_se050_session_release(void);

/**
 * @brief  Check if the SE050 session is alive.
 *
 * @return
 *    - ESP_OK if session is healthy
 *    - ESP_FAIL if session is stale
 *    - ESP_ERR_INVALID_STATE if no session is open
 */
esp_err_t esp_se050_session_check(void);

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

/**
 * @brief  Generate a DER-encoded reference key for any supported EC curve.
 */
esp_err_t esp_se050_make_refkey(esp_se050_ec_curve_t curve,
    uint32_t key_id,
    const uint8_t *pubkey_uncompressed,
    size_t pubkey_len,
    uint8_t *out_der_key,
    size_t *out_der_key_len);

#if CONFIG_SE050_DERIVE_KEY
/**
 * @brief  Derive a key using SE050-backed ECDH + HKDF-SHA256.
 *
 * Performs deterministic key derivation: SHA-256(context) is used as a
 * scalar to compute an ephemeral EC point, then ECDH is performed with
 * the SE050 private key, and finally HKDF-SHA256 produces the output.
 *
 * @param[in]  dek_key_id  SE050 object ID of the EC key pair for derivation
 * @param[in]  context     Context/info data for HKDF
 * @param[in]  context_len Length of context
 * @param[out] out         Output key material
 * @param[in]  out_len     Desired output length (typically 32)
 *
 * @return ESP_OK on success
 */
esp_err_t esp_se050_derive_key(uint32_t dek_key_id,
    const uint8_t *context, size_t context_len,
    uint8_t *out, size_t out_len);
#endif

#ifdef __cplusplus
}
#endif
