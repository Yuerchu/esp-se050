/** @file sm_timer.c
 *  @brief Timer APIs for ESP-IDF.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sm_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_rom_sys.h"

uint32_t sm_initSleep(void)
{
    return 0;
}

void sm_sleep(uint32_t msec)
{
    vTaskDelay(pdMS_TO_TICKS(msec));
}

void sm_usleep(uint32_t microsec)
{
    if (microsec < 1000) {
        esp_rom_delay_us(microsec);
        return;
    }
    vTaskDelay(pdMS_TO_TICKS(microsec / 1000));
}
