/** @file sm_i2c.c
 *  @brief I2C Interface functions for ESP-IDF.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include "sm_i2c.h"
#include "sm_port.h"

#include "driver/i2c_master.h"

typedef struct {
    i2c_master_bus_handle_t bus_handle;
    i2c_master_dev_handle_t dev_handle;
    int refcount;
} esp_se050_i2c_ctx_t;

static esp_se050_i2c_ctx_t s_i2c_ctx;

static bool i2c_ctx_ready(void)
{
    return s_i2c_ctx.bus_handle != NULL && s_i2c_ctx.dev_handle != NULL;
}

i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName)
{
    (void)pDevName;

    if (i2c_ctx_ready()) {
        s_i2c_ctx.refcount++;
        if (conn_ctx) {
            *conn_ctx = &s_i2c_ctx;
        }
        return I2C_OK;
    }

    i2c_master_bus_config_t bus_cfg = {
        .i2c_port = CONFIG_SE050_I2C_PORT,
        .sda_io_num = CONFIG_SE050_I2C_SDA_PIN,
        .scl_io_num = CONFIG_SE050_I2C_SCL_PIN,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };

    esp_err_t ret = i2c_new_master_bus(&bus_cfg, &s_i2c_ctx.bus_handle);
    if (ret != ESP_OK) {
        SMLOG_E("i2c_new_master_bus failed: %d", ret);
        return I2C_FAILED;
    }

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = CONFIG_SE050_I2C_ADDR,
        .scl_speed_hz = CONFIG_SE050_I2C_CLOCK_HZ,
    };

    ret = i2c_master_bus_add_device(s_i2c_ctx.bus_handle, &dev_cfg, &s_i2c_ctx.dev_handle);
    if (ret != ESP_OK) {
        SMLOG_E("i2c_master_bus_add_device failed: %d", ret);
        i2c_del_master_bus(s_i2c_ctx.bus_handle);
        s_i2c_ctx.bus_handle = NULL;
        return I2C_FAILED;
    }

    s_i2c_ctx.refcount = 1;
    if (conn_ctx) {
        *conn_ctx = &s_i2c_ctx;
    }
    return I2C_OK;
}

void axI2CTerm(void *conn_ctx, int mode)
{
    (void)conn_ctx;
    (void)mode;

    if (!i2c_ctx_ready()) {
        return;
    }

    if (s_i2c_ctx.refcount > 0) {
        s_i2c_ctx.refcount--;
    }

    if (s_i2c_ctx.refcount == 0) {
        i2c_master_bus_rm_device(s_i2c_ctx.dev_handle);
        i2c_del_master_bus(s_i2c_ctx.bus_handle);
        s_i2c_ctx.dev_handle = NULL;
        s_i2c_ctx.bus_handle = NULL;
    }
}

i2c_error_t axI2CWrite(void *conn_ctx, unsigned char bus, unsigned char addr,
    unsigned char *pTx, unsigned short txLen)
{
    (void)conn_ctx;
    (void)bus;
    (void)addr;

    if (!i2c_ctx_ready()) {
        return I2C_FAILED;
    }

    esp_err_t ret = i2c_master_transmit(s_i2c_ctx.dev_handle, pTx, txLen, -1);
    return (ret == ESP_OK) ? I2C_OK : I2C_FAILED;
}

i2c_error_t axI2CRead(void *conn_ctx, unsigned char bus, unsigned char addr,
    unsigned char *pRx, unsigned short rxLen)
{
    (void)conn_ctx;
    (void)bus;
    (void)addr;

    if (!i2c_ctx_ready()) {
        return I2C_FAILED;
    }

    esp_err_t ret = i2c_master_receive(s_i2c_ctx.dev_handle, pRx, rxLen, -1);
    return (ret == ESP_OK) ? I2C_OK : I2C_FAILED;
}
