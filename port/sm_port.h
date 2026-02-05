/** @file sm_port.h
 *  @brief Platform specific content for ESP-IDF.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SM_PORT_H_INC
#define SM_PORT_H_INC

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#ifndef CONFIG_SE050_LOG_LEVEL
#define CONFIG_SE050_LOG_LEVEL 3
#endif

#define SMLOG_TAG "se050"

#if CONFIG_SE050_LOG_LEVEL >= 3
#define SMLOG_I(...) ESP_LOGI(SMLOG_TAG, __VA_ARGS__)
#else
#define SMLOG_I(...)
#endif

#if CONFIG_SE050_LOG_LEVEL >= 1
#define SMLOG_E(...) ESP_LOGE(SMLOG_TAG, __VA_ARGS__)
#else
#define SMLOG_E(...)
#endif

#if CONFIG_SE050_LOG_LEVEL >= 2
#define SMLOG_W(...) ESP_LOGW(SMLOG_TAG, __VA_ARGS__)
#else
#define SMLOG_W(...)
#endif

#if CONFIG_SE050_LOG_LEVEL >= 4
#define SMLOG_D(...) ESP_LOGD(SMLOG_TAG, __VA_ARGS__)
#define SMLOG_AU8_D(BUF, LEN) ESP_LOG_BUFFER_HEX_LEVEL(SMLOG_TAG, BUF, LEN, ESP_LOG_DEBUG)
#define SMLOG_MAU8_D(MSG, BUF, LEN) \
    do {                                \
        ESP_LOGD(SMLOG_TAG, "%s", MSG); \
        ESP_LOG_BUFFER_HEX_LEVEL(SMLOG_TAG, BUF, LEN, ESP_LOG_DEBUG); \
    } while (0)
#else
#define SMLOG_D(...)
#define SMLOG_AU8_D(BUF, LEN)
#define SMLOG_MAU8_D(MSG, BUF, LEN)
#endif

#define sm_malloc(x) heap_caps_malloc((x), MALLOC_CAP_DEFAULT)
#define sm_free(x) free((x))

#define SM_MUTEX_DEFINE(x) SemaphoreHandle_t x
#define SM_MUTEX_EXTERN_DEFINE(x) extern SemaphoreHandle_t x
#define SM_MUTEX_INIT(x)                      \
    do {                                      \
        if ((x) == NULL) {                    \
            (x) = xSemaphoreCreateMutex();   \
        }                                     \
    } while (0)
#define SM_MUTEX_DEINIT(x)                   \
    do {                                      \
        if ((x) != NULL) {                    \
            vSemaphoreDelete((x));            \
            (x) = NULL;                       \
        }                                     \
    } while (0)
#define SM_MUTEX_LOCK(x)                     \
    do {                                      \
        if ((x) != NULL) {                    \
            xSemaphoreTake((x), portMAX_DELAY); \
        }                                     \
    } while (0)
#define SM_MUTEX_UNLOCK(x)                   \
    do {                                      \
        if ((x) != NULL) {                    \
            xSemaphoreGive((x));              \
        }                                     \
    } while (0)

#ifndef FALSE
#define FALSE false
#endif

#ifndef TRUE
#define TRUE true
#endif

#endif // SM_PORT_H_INC
