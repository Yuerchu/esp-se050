/*
 * Copyright 2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "se05x_mbedtls.h"
#include <sm_port.h>
#include "se05x_APDU_apis.h"
#include "esp_se050.h"
#include <string.h>


smStatus_t se05x_open_session(void)
{
    if (pSession.conn_context != NULL) {
        return SM_OK;
    }

    SMLOG_I("Open Session to SE05x \n");
    esp_err_t err = esp_se050_session_acquire(NULL);
    return (err == ESP_OK) ? SM_OK : SM_NOT_OK;
}

smStatus_t se05x_close_session(void)
{
    esp_se050_session_release();
    return SM_OK;
}
