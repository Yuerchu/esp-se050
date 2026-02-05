#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct esp_se050_session_cfg {
    const uint8_t *scp03_enc_key;
    const uint8_t *scp03_mac_key;
    const uint8_t *scp03_dek_key;

    const uint8_t *ec_key;
    size_t ec_key_len;

    bool session_resume;
} esp_se050_session_cfg_t;
