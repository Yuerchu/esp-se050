#include "esp_se050.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "esp_tls.h"

#include "se05x_APDU_apis.h"
#include "se05x_mbedtls.h"

static const char *TAG = "esp-se050";

Se05xSession_t pSession;
static int s_refcount = 0;
static SemaphoreHandle_t s_session_mutex;

#define ESP_SE050_MAX_CERT_SIZE 4096

static void session_lock(void)
{
    if (s_session_mutex == NULL) {
        s_session_mutex = xSemaphoreCreateMutex();
    }
    if (s_session_mutex != NULL) {
        xSemaphoreTake(s_session_mutex, portMAX_DELAY);
    }
}

static void session_unlock(void)
{
    if (s_session_mutex != NULL) {
        xSemaphoreGive(s_session_mutex);
    }
}

static esp_err_t session_configure(const esp_se050_session_cfg_t *cfg)
{
#if CONFIG_SE050_SCP03 || CONFIG_SE050_ECKEY_SCP03
    if (cfg == NULL || cfg->scp03_enc_key == NULL || cfg->scp03_mac_key == NULL || cfg->scp03_dek_key == NULL) {
        ESP_LOGE(TAG, "SCP03 keys are required but not provided");
        return ESP_ERR_INVALID_ARG;
    }
    pSession.pScp03_enc_key = (uint8_t *)cfg->scp03_enc_key;
    pSession.pScp03_mac_key = (uint8_t *)cfg->scp03_mac_key;
    pSession.pScp03_dek_key = (uint8_t *)cfg->scp03_dek_key;
#endif

#if CONFIG_SE050_ECKEY || CONFIG_SE050_ECKEY_SCP03
    if (cfg == NULL || cfg->ec_key == NULL || cfg->ec_key_len == 0) {
        ESP_LOGE(TAG, "EC Key auth key is required but not provided");
        return ESP_ERR_INVALID_ARG;
    }
    pSession.pEc_auth_key = (uint8_t *)cfg->ec_key;
    pSession.ec_auth_key_len = cfg->ec_key_len;
#endif

    if (cfg != NULL) {
        pSession.session_resume = cfg->session_resume ? 1 : 0;
    }
    return ESP_OK;
}

esp_err_t esp_se050_session_acquire(const esp_se050_session_cfg_t *cfg)
{
    session_lock();

    if (s_refcount > 0 && pSession.conn_context != NULL) {
        s_refcount++;
        session_unlock();
        return ESP_OK;
    }

    memset(&pSession, 0, sizeof(pSession));

    esp_err_t cfg_ret = session_configure(cfg);
    if (cfg_ret != ESP_OK) {
        session_unlock();
        return cfg_ret;
    }

    smStatus_t status = Se05x_API_SessionOpen(&pSession);
    if (status != SM_OK) {
        ESP_LOGE(TAG, "Se05x_API_SessionOpen failed: %d", status);
        session_unlock();
        return ESP_FAIL;
    }

    s_refcount = 1;
    session_unlock();
    return ESP_OK;
}

void esp_se050_session_release(void)
{
    session_lock();
    if (s_refcount > 0) {
        s_refcount--;
    }
    if (s_refcount == 0 && pSession.conn_context != NULL) {
        Se05x_API_SessionClose(&pSession);
        memset(&pSession, 0, sizeof(pSession));
    }
    session_unlock();
}

esp_err_t esp_se050_read_object(uint32_t object_id, uint8_t *buf, size_t *len)
{
    if (buf == NULL || len == NULL || *len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (pSession.conn_context == NULL) {
        ESP_LOGE(TAG, "SE050 session not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    size_t out_len = *len;
    smStatus_t status = Se05x_API_ReadObject(&pSession, object_id, 0, (uint16_t)*len, buf, &out_len);
    if (status != SM_OK) {
        ESP_LOGE(TAG, "Se05x_API_ReadObject failed: %d", status);
        return ESP_FAIL;
    }
    *len = out_len;
    return ESP_OK;
}

static esp_err_t read_cert_from_se050(uint32_t cert_id, uint8_t **out_buf, size_t *out_len)
{
    uint8_t *buf = malloc(ESP_SE050_MAX_CERT_SIZE);
    if (!buf) {
        return ESP_ERR_NO_MEM;
    }

    size_t total = 0;
    size_t chunk = 512;
    while (total < ESP_SE050_MAX_CERT_SIZE) {
        size_t want = (ESP_SE050_MAX_CERT_SIZE - total) < chunk ? (ESP_SE050_MAX_CERT_SIZE - total) : chunk;
        size_t got = want;
        smStatus_t status = Se05x_API_ReadObject(&pSession, cert_id, (uint16_t)total, (uint16_t)want, buf + total, &got);
        if (status != SM_OK) {
            free(buf);
            ESP_LOGE(TAG, "Se05x_API_ReadObject failed: %d", status);
            return ESP_FAIL;
        }
        if (got == 0) {
            break;
        }
        total += got;
        if (got < want) {
            break;
        }
    }

    if (total == 0) {
        free(buf);
        return ESP_FAIL;
    }

    *out_buf = buf;
    *out_len = total;
    return ESP_OK;
}

esp_err_t esp_se050_make_refkey_p256(uint32_t key_id,
    const uint8_t *pubkey_uncompressed,
    size_t pubkey_len,
    uint8_t *out_der_key,
    size_t *out_der_key_len)
{
    if (pubkey_uncompressed == NULL || out_der_key == NULL || out_der_key_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (pubkey_len != 65) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t ref_priv[32] = {0};
    uint8_t magic[] = ALT_KEYS_MAGIC;

    ref_priv[0] = 0x10;
    ref_priv[31] = 0x00;
    ref_priv[30] = 0x10;

    size_t magic_offset = 32 - sizeof(magic) - 2;
    memcpy(&ref_priv[magic_offset], magic, sizeof(magic));

    size_t id_offset = magic_offset - 4;
    ref_priv[id_offset + 0] = (uint8_t)((key_id >> 24) & 0xFF);
    ref_priv[id_offset + 1] = (uint8_t)((key_id >> 16) & 0xFF);
    ref_priv[id_offset + 2] = (uint8_t)((key_id >> 8) & 0xFF);
    ref_priv[id_offset + 3] = (uint8_t)(key_id & 0xFF);

    static const uint8_t header1[] = {
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
        0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,
        0x01, 0x01, 0x04, 0x20
    };
    static const uint8_t header2[] = {0xA1, 0x44, 0x03, 0x42, 0x00};

    size_t needed = sizeof(header1) + sizeof(ref_priv) + sizeof(header2) + pubkey_len;
    if (*out_der_key_len < needed) {
        *out_der_key_len = needed;
        return ESP_ERR_NO_MEM;
    }

    size_t idx = 0;
    memcpy(out_der_key + idx, header1, sizeof(header1));
    idx += sizeof(header1);
    memcpy(out_der_key + idx, ref_priv, sizeof(ref_priv));
    idx += sizeof(ref_priv);
    memcpy(out_der_key + idx, header2, sizeof(header2));
    idx += sizeof(header2);
    memcpy(out_der_key + idx, pubkey_uncompressed, pubkey_len);
    idx += pubkey_len;

    *out_der_key_len = idx;
    return ESP_OK;
}

static esp_err_t extract_pubkey_p256(mbedtls_x509_crt *crt, uint8_t *pubkey, size_t *pubkey_len)
{
    if (crt == NULL || pubkey == NULL || pubkey_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (mbedtls_pk_get_type(&crt->pk) != MBEDTLS_PK_ECKEY) {
        return ESP_ERR_INVALID_STATE;
    }

    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(crt->pk);
    if (ecp->MBEDTLS_PRIVATE(grp).id != MBEDTLS_ECP_DP_SECP256R1) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    size_t len = 0;
    int ret = mbedtls_ecp_point_write_binary(&ecp->MBEDTLS_PRIVATE(grp),
        &ecp->MBEDTLS_PRIVATE(Q),
        MBEDTLS_ECP_PF_UNCOMPRESSED,
        &len,
        pubkey,
        *pubkey_len);
    if (ret != 0) {
        return ESP_FAIL;
    }
    *pubkey_len = len;
    return ESP_OK;
}

esp_err_t esp_se050_tls_pki_setup(mbedtls_ssl_config *conf,
    mbedtls_x509_crt *cert,
    mbedtls_pk_context *key,
    const void *cfg)
{
    if (conf == NULL || cert == NULL || key == NULL || cfg == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    const esp_tls_cfg_t *tls_cfg = (const esp_tls_cfg_t *)cfg;

    esp_err_t err = esp_se050_session_acquire(tls_cfg->se050_session_cfg);
    if (err != ESP_OK) {
        return err;
    }

    mbedtls_x509_crt_init(cert);
    mbedtls_pk_init(key);

    uint8_t *cert_buf = NULL;
    size_t cert_len = 0;

    if (tls_cfg->clientcert_buf != NULL && tls_cfg->clientcert_bytes > 0) {
        ESP_LOGW(TAG, "clientcert_buf is used instead of SE050 cert object");
        cert_buf = (uint8_t *)tls_cfg->clientcert_buf;
        cert_len = tls_cfg->clientcert_bytes;
    } else if (tls_cfg->se050_cert_id != 0) {
        err = read_cert_from_se050(tls_cfg->se050_cert_id, &cert_buf, &cert_len);
        if (err != ESP_OK) {
            esp_se050_session_release();
            return err;
        }
    } else {
        ESP_LOGE(TAG, "No client certificate provided");
        esp_se050_session_release();
        return ESP_ERR_INVALID_ARG;
    }

    int ret = mbedtls_x509_crt_parse(cert, cert_buf, cert_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse failed: %d", ret);
        if (cert_buf != tls_cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return ESP_FAIL;
    }

    uint8_t pubkey[65] = {0};
    size_t pubkey_len = sizeof(pubkey);
    err = extract_pubkey_p256(cert, pubkey, &pubkey_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unsupported public key type/curve");
        if (cert_buf != tls_cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return err;
    }

    uint8_t refkey_der[256] = {0};
    size_t refkey_len = sizeof(refkey_der);
    err = esp_se050_make_refkey_p256(tls_cfg->se050_key_id, pubkey, pubkey_len, refkey_der, &refkey_len);
    if (err != ESP_OK) {
        if (cert_buf != tls_cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return err;
    }

    ret = mbedtls_pk_parse_key(key, refkey_der, refkey_len, NULL, 0, NULL, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_pk_parse_key failed: %d", ret);
        if (cert_buf != tls_cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return ESP_FAIL;
    }

    ret = mbedtls_ssl_conf_own_cert(conf, cert, key);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_conf_own_cert failed: %d", ret);
        if (cert_buf != tls_cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return ESP_FAIL;
    }

    if (cert_buf != tls_cfg->clientcert_buf) {
        free(cert_buf);
    }

    return ESP_OK;
}
