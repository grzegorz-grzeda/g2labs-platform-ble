/*
 * MIT License
 *
 * Copyright (c) 2023 G2Labs Grzegorz Grzęda
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef G2LABS_PLATFORM_BLE_H
#define G2LABS_PLATFORM_BLE_H

#include <stdint.h>

typedef struct platform_ble_scan_entry {
    uint8_t mac[6];
    int rssi;
    uint8_t adv_data[64];
    uint8_t adv_data_size;
} platform_ble_scan_entry_t;

typedef void (*platform_ble_scan_entry_handler_t)(platform_ble_scan_entry_t* entry);

void platform_ble_initialize(void);

void platform_ble_scan_start(platform_ble_scan_entry_handler_t handler);

void platform_ble_scan_stop(void);

#endif  // G2LABS_PLATFORM_BLE_H