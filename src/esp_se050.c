#include "esp_se050.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

#include "se05x_APDU_apis.h"
#include "se05x_mbedtls.h"

static const char *TAG = "esp-se050";

Se05xSession_t pSession;
static int s_refcount = 0;
static portMUX_TYPE s_init_mux = portMUX_INITIALIZER_UNLOCKED;
static SemaphoreHandle_t s_session_mutex = NULL;
static esp_se050_session_cfg_t s_active_cfg;
static bool s_has_active_cfg = false;

#define SCP03_KEY_LEN 16
#define EC_KEY_MAX_LEN 256
static uint8_t s_key_store[3 * SCP03_KEY_LEN + EC_KEY_MAX_LEN];

#define ESP_SE050_MAX_CERT_SIZE 4096

static void session_lock(void)
{
    if (s_session_mutex == NULL) {
        portENTER_CRITICAL(&s_init_mux);
        if (s_session_mutex == NULL) {
            s_session_mutex = xSemaphoreCreateMutex();
        }
        portEXIT_CRITICAL(&s_init_mux);
    }
    xSemaphoreTake(s_session_mutex, portMAX_DELAY);
}

static void session_unlock(void)
{
    xSemaphoreGive(s_session_mutex);
}

static esp_err_t session_cfg_deep_copy(const esp_se050_session_cfg_t *cfg)
{
    memcpy(&s_active_cfg, cfg, sizeof(esp_se050_session_cfg_t));
    memset(s_key_store, 0, sizeof(s_key_store));

    size_t offset = 0;

    if (cfg->scp03_enc_key != NULL) {
        memcpy(s_key_store + offset, cfg->scp03_enc_key, SCP03_KEY_LEN);
        s_active_cfg.scp03_enc_key = s_key_store + offset;
        offset += SCP03_KEY_LEN;
    }
    if (cfg->scp03_mac_key != NULL) {
        memcpy(s_key_store + offset, cfg->scp03_mac_key, SCP03_KEY_LEN);
        s_active_cfg.scp03_mac_key = s_key_store + offset;
        offset += SCP03_KEY_LEN;
    }
    if (cfg->scp03_dek_key != NULL) {
        memcpy(s_key_store + offset, cfg->scp03_dek_key, SCP03_KEY_LEN);
        s_active_cfg.scp03_dek_key = s_key_store + offset;
        offset += SCP03_KEY_LEN;
    }
    if (cfg->ec_key != NULL && cfg->ec_key_len > 0) {
        if (cfg->ec_key_len > EC_KEY_MAX_LEN) {
            ESP_LOGE(TAG, "EC key too large: %u > %u", (unsigned)cfg->ec_key_len, (unsigned)EC_KEY_MAX_LEN);
            memset(&s_active_cfg, 0, sizeof(s_active_cfg));
            memset(s_key_store, 0, sizeof(s_key_store));
            return ESP_ERR_INVALID_ARG;
        }
        memcpy(s_key_store + offset, cfg->ec_key, cfg->ec_key_len);
        s_active_cfg.ec_key = s_key_store + offset;
    }
    return ESP_OK;
}

static bool session_cfg_compatible(const esp_se050_session_cfg_t *a, const esp_se050_session_cfg_t *b)
{
    if (a == NULL && b == NULL) {
        return true;
    }
    if (a == NULL || b == NULL) {
        return false;
    }

    // Compare SCP03 keys: both NULL or both non-NULL with matching content
    bool a_has_scp03 = (a->scp03_enc_key != NULL);
    bool b_has_scp03 = (b->scp03_enc_key != NULL);
    if (a_has_scp03 != b_has_scp03) {
        return false;
    }
    if (a_has_scp03) {
        if ((a->scp03_mac_key == NULL) != (b->scp03_mac_key == NULL)) {
            return false;
        }
        if ((a->scp03_dek_key == NULL) != (b->scp03_dek_key == NULL)) {
            return false;
        }
        if (memcmp(a->scp03_enc_key, b->scp03_enc_key, 16) != 0) {
            return false;
        }
        if (a->scp03_mac_key != NULL && memcmp(a->scp03_mac_key, b->scp03_mac_key, 16) != 0) {
            return false;
        }
        if (a->scp03_dek_key != NULL && memcmp(a->scp03_dek_key, b->scp03_dek_key, 16) != 0) {
            return false;
        }
    }

    // Compare EC key
    if (a->ec_key_len != b->ec_key_len) {
        return false;
    }
    if (a->ec_key_len > 0) {
        if ((a->ec_key == NULL) != (b->ec_key == NULL)) {
            return false;
        }
        if (a->ec_key != NULL && memcmp(a->ec_key, b->ec_key, a->ec_key_len) != 0) {
            return false;
        }
    }

    return true;
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
        // Check configuration compatibility
        if (cfg == NULL && s_has_active_cfg) {
            ESP_LOGE(TAG, "Session active with secure cfg, but plaintext requested");
            session_unlock();
            return ESP_ERR_INVALID_STATE;
        }
        if (cfg != NULL && !s_has_active_cfg) {
            ESP_LOGE(TAG, "Session active with plaintext, but secure cfg requested");
            session_unlock();
            return ESP_ERR_INVALID_STATE;
        }
        if (cfg != NULL && s_has_active_cfg && !session_cfg_compatible(cfg, &s_active_cfg)) {
            ESP_LOGE(TAG, "Session active with incompatible configuration");
            session_unlock();
            return ESP_ERR_INVALID_STATE;
        }
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

    if (cfg != NULL) {
        esp_err_t copy_ret = session_cfg_deep_copy(cfg);
        if (copy_ret != ESP_OK) {
            Se05x_API_SessionClose(&pSession);
            memset(&pSession, 0, sizeof(pSession));
            s_refcount = 0;
            session_unlock();
            return copy_ret;
        }
        s_has_active_cfg = true;
    } else {
        memset(&s_active_cfg, 0, sizeof(esp_se050_session_cfg_t));
        memset(s_key_store, 0, sizeof(s_key_store));
        s_has_active_cfg = false;
    }

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
        memset(s_key_store, 0, sizeof(s_key_store));
        memset(&s_active_cfg, 0, sizeof(s_active_cfg));
        s_has_active_cfg = false;
    }
    session_unlock();
}

static esp_err_t session_health_check(void)
{
    if (pSession.conn_context == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t version[8] = {0};
    size_t version_len = sizeof(version);
    smStatus_t status = Se05x_API_GetVersion(&pSession, version, &version_len);
    return (status == SM_OK) ? ESP_OK : ESP_FAIL;
}

static esp_err_t session_reconnect(void)
{
    ESP_LOGW(TAG, "Session stale, attempting reconnect");
    Se05x_API_SessionClose(&pSession);
    memset(&pSession, 0, sizeof(pSession));

    if (s_has_active_cfg) {
        esp_err_t ret = session_configure(&s_active_cfg);
        if (ret != ESP_OK) {
            return ret;
        }
    }

    smStatus_t status = Se05x_API_SessionOpen(&pSession);
    if (status != SM_OK) {
        ESP_LOGE(TAG, "Reconnect failed: %d", status);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Session reconnected successfully");
    return ESP_OK;
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
        ESP_LOGW(TAG, "ReadObject failed (status=%d), trying reconnect", status);
        if (session_reconnect() == ESP_OK) {
            out_len = *len;
            status = Se05x_API_ReadObject(&pSession, object_id, 0, (uint16_t)*len, buf, &out_len);
        }
        if (status != SM_OK) {
            ESP_LOGE(TAG, "Se05x_API_ReadObject failed: %d", status);
            return ESP_FAIL;
        }
    }
    *len = out_len;
    return ESP_OK;
}

esp_err_t esp_se050_session_check(void)
{
    session_lock();
    esp_err_t ret = session_health_check();
    session_unlock();
    return ret;
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

// P-256 PKCS#8 DER template
static const uint8_t s_p256_header1[] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,
    0x01, 0x01, 0x04, 0x20
};
static const uint8_t s_p256_header2[] = {0xA1, 0x44, 0x03, 0x42, 0x00};

// P-384 PKCS#8 DER template
static const uint8_t s_p384_header1[] = {
    0x30, 0x81, 0xb6,
    0x02, 0x01, 0x00,
    0x30, 0x10,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
    0x04, 0x81, 0x9e,
    0x30, 0x81, 0x9b,
    0x02, 0x01, 0x01,
    0x04, 0x30
};
static const uint8_t s_p384_header2[] = {0xA1, 0x64, 0x03, 0x62, 0x00};

typedef struct {
    size_t scalar_len;
    size_t point_len;
    uint8_t curve_tag;
    const uint8_t *header1;
    size_t header1_len;
    const uint8_t *header2;
    size_t header2_len;
} ec_curve_params_t;

esp_err_t esp_se050_make_refkey(esp_se050_ec_curve_t curve,
    uint32_t key_id,
    const uint8_t *pubkey_uncompressed,
    size_t pubkey_len,
    uint8_t *out_der_key,
    size_t *out_der_key_len)
{
    if (pubkey_uncompressed == NULL || out_der_key == NULL || out_der_key_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    const ec_curve_params_t *params = NULL;

    static const ec_curve_params_t s_p256_params = {
        .scalar_len = 32,
        .point_len = 65,
        .curve_tag = 0x01,
        .header1 = s_p256_header1,
        .header1_len = sizeof(s_p256_header1),
        .header2 = s_p256_header2,
        .header2_len = sizeof(s_p256_header2),
    };

    static const ec_curve_params_t s_p384_params = {
        .scalar_len = 48,
        .point_len = 97,
        .curve_tag = 0x02,
        .header1 = s_p384_header1,
        .header1_len = sizeof(s_p384_header1),
        .header2 = s_p384_header2,
        .header2_len = sizeof(s_p384_header2),
    };

    switch (curve) {
    case ESP_SE050_EC_P256:
        params = &s_p256_params;
        break;
    case ESP_SE050_EC_P384:
        params = &s_p384_params;
        break;
    default:
        ESP_LOGE(TAG, "Unsupported EC curve: %d", (int)curve);
        return ESP_ERR_NOT_SUPPORTED;
    }

    if (pubkey_len != params->point_len) {
        ESP_LOGE(TAG, "Invalid pubkey length: expected %u, got %u",
            (unsigned)params->point_len, (unsigned)pubkey_len);
        return ESP_ERR_INVALID_ARG;
    }

    size_t n = params->scalar_len;
    uint8_t ref_priv[48] = {0};

    uint8_t magic[] = ALT_KEYS_MAGIC;

    ref_priv[0] = 0x10;
    ref_priv[n - 1] = 0x00;
    ref_priv[n - 2] = 0x10;

    size_t magic_offset = n - sizeof(magic) - 2;
    memcpy(&ref_priv[magic_offset], magic, sizeof(magic));

    size_t tag_offset = magic_offset - 1;
    ref_priv[tag_offset] = params->curve_tag;

    size_t id_offset = tag_offset - 4;
    ref_priv[id_offset + 0] = (uint8_t)((key_id >> 24) & 0xFF);
    ref_priv[id_offset + 1] = (uint8_t)((key_id >> 16) & 0xFF);
    ref_priv[id_offset + 2] = (uint8_t)((key_id >> 8) & 0xFF);
    ref_priv[id_offset + 3] = (uint8_t)(key_id & 0xFF);

    size_t needed = params->header1_len + n + params->header2_len + pubkey_len;
    if (*out_der_key_len < needed) {
        *out_der_key_len = needed;
        return ESP_ERR_NO_MEM;
    }

    size_t idx = 0;
    memcpy(out_der_key + idx, params->header1, params->header1_len);
    idx += params->header1_len;
    memcpy(out_der_key + idx, ref_priv, n);
    idx += n;
    memcpy(out_der_key + idx, params->header2, params->header2_len);
    idx += params->header2_len;
    memcpy(out_der_key + idx, pubkey_uncompressed, pubkey_len);
    idx += pubkey_len;

    *out_der_key_len = idx;
    return ESP_OK;
}

esp_err_t esp_se050_make_refkey_p256(uint32_t key_id,
    const uint8_t *pubkey_uncompressed,
    size_t pubkey_len,
    uint8_t *out_der_key,
    size_t *out_der_key_len)
{
    return esp_se050_make_refkey(ESP_SE050_EC_P256, key_id,
        pubkey_uncompressed, pubkey_len, out_der_key, out_der_key_len);
}

static esp_err_t extract_pubkey_ec(mbedtls_x509_crt *crt,
    uint8_t *pubkey, size_t *pubkey_len, esp_se050_ec_curve_t *out_curve)
{
    if (crt == NULL || pubkey == NULL || pubkey_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (mbedtls_pk_get_type(&crt->pk) != MBEDTLS_PK_ECKEY) {
        return ESP_ERR_INVALID_STATE;
    }

    unsigned char tmp[256];
    unsigned char *p = tmp + sizeof(tmp);
    int len = mbedtls_pk_write_pubkey(&p, tmp, &crt->pk);
    if (len < 0 || *p != 0x04) {
        return ESP_FAIL;
    }

    esp_se050_ec_curve_t curve;
    if (len == 65) {
        curve = ESP_SE050_EC_P256;
    } else if (len == 97) {
        curve = ESP_SE050_EC_P384;
    } else {
        ESP_LOGE(TAG, "Unsupported EC key size (len=%d)", len);
        return ESP_ERR_NOT_SUPPORTED;
    }

    if ((size_t)len > *pubkey_len) {
        return ESP_ERR_NO_MEM;
    }

    memcpy(pubkey, p, len);
    *pubkey_len = (size_t)len;
    if (out_curve) {
        *out_curve = curve;
    }
    return ESP_OK;
}

esp_err_t esp_se050_tls_pki_setup(mbedtls_ssl_config *conf,
    mbedtls_x509_crt *cert,
    mbedtls_pk_context *key,
    const esp_se050_tls_cfg_t *cfg)
{
    if (conf == NULL || cert == NULL || key == NULL || cfg == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = esp_se050_session_acquire(cfg->session_cfg);
    if (err != ESP_OK) {
        return err;
    }

    mbedtls_x509_crt_init(cert);
    mbedtls_pk_init(key);

    uint8_t *cert_buf = NULL;
    size_t cert_len = 0;

    if (cfg->clientcert_buf != NULL && cfg->clientcert_bytes > 0) {
        ESP_LOGW(TAG, "clientcert_buf is used instead of SE050 cert object");
        cert_buf = (uint8_t *)cfg->clientcert_buf;
        cert_len = cfg->clientcert_bytes;
    } else if (cfg->cert_id != 0) {
        err = read_cert_from_se050(cfg->cert_id, &cert_buf, &cert_len);
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
        if (cert_buf != cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return ESP_FAIL;
    }

    uint8_t pubkey[97] = {0};
    size_t pubkey_len = sizeof(pubkey);
    esp_se050_ec_curve_t curve;
    err = extract_pubkey_ec(cert, pubkey, &pubkey_len, &curve);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unsupported public key type/curve");
        if (cert_buf != cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return err;
    }

    uint8_t refkey_der[384] = {0};
    size_t refkey_len = sizeof(refkey_der);
    err = esp_se050_make_refkey(curve, cfg->key_id, pubkey, pubkey_len, refkey_der, &refkey_len);
    if (err != ESP_OK) {
        if (cert_buf != cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return err;
    }

    ret = mbedtls_pk_parse_key(key, refkey_der, refkey_len, NULL, 0, NULL, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_pk_parse_key failed: %d", ret);
        if (cert_buf != cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return ESP_FAIL;
    }

    ret = mbedtls_ssl_conf_own_cert(conf, cert, key);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_conf_own_cert failed: %d", ret);
        if (cert_buf != cfg->clientcert_buf) {
            free(cert_buf);
        }
        esp_se050_session_release();
        return ESP_FAIL;
    }

    if (cert_buf != cfg->clientcert_buf) {
        free(cert_buf);
    }

    return ESP_OK;
}

#if CONFIG_SE050_DERIVE_KEY

#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

esp_err_t esp_se050_derive_key(uint32_t dek_key_id,
    const uint8_t *context, size_t context_len,
    uint8_t *out, size_t out_len)
{
    if (context == NULL || out == NULL || out_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (pSession.conn_context == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    // Step 1: Derive a deterministic scalar from context
    uint8_t seed[32];
    int ret = mbedtls_sha256(context, context_len, seed, 0);
    if (ret != 0) {
        return ESP_FAIL;
    }

    // Step 2: Compute ephemeral public key Q = seed * G on P-256
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d_scalar;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d_scalar);

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        goto cleanup_ecp;
    }

    ret = mbedtls_mpi_read_binary(&d_scalar, seed, 32);
    if (ret != 0) {
        goto cleanup_ecp;
    }

    // Ensure scalar is in [1, n-1]
    ret = mbedtls_mpi_mod_mpi(&d_scalar, &d_scalar, &grp.N);
    if (ret != 0) {
        goto cleanup_ecp;
    }
    if (mbedtls_mpi_cmp_int(&d_scalar, 0) == 0) {
        mbedtls_mpi_lset(&d_scalar, 1);
    }

    ret = mbedtls_ecp_mul(&grp, &Q, &d_scalar, &grp.G, NULL, NULL);
    if (ret != 0) {
        goto cleanup_ecp;
    }

    // Export uncompressed public key
    uint8_t ephem_pubkey[65];
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
        &olen, ephem_pubkey, sizeof(ephem_pubkey));
    if (ret != 0 || olen != 65) {
        goto cleanup_ecp;
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d_scalar);

    // Step 3: SE050 ECDH
    uint8_t shared_secret[32];
    size_t shared_len = sizeof(shared_secret);
    smStatus_t sm_status = Se05x_API_ECDHGenerateSharedSecret(
        &pSession, dek_key_id, ephem_pubkey, olen, shared_secret, &shared_len);
    if (sm_status != SM_OK) {
        ESP_LOGE(TAG, "ECDH failed: %d", sm_status);
        mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
        return ESP_FAIL;
    }

    // Step 4: HKDF-SHA256
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ret = mbedtls_hkdf(md_info,
        NULL, 0,                          // salt (none)
        shared_secret, shared_len,        // IKM
        context, context_len,             // info
        out, out_len);

    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
    mbedtls_platform_zeroize(seed, sizeof(seed));

    return (ret == 0) ? ESP_OK : ESP_FAIL;

cleanup_ecp:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d_scalar);
    mbedtls_platform_zeroize(seed, sizeof(seed));
    return ESP_FAIL;
}

#endif // CONFIG_SE050_DERIVE_KEY
