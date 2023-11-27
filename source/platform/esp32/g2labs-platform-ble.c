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
#include "g2labs-platform-ble.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_err.h"
#include "esp_gap_ble_api.h"

#define G2LABS_LOG_MODULE_LEVEL (LOG_MODULE_LEVEL_INFO)
#define G2LABS_LOG_MODULE_NAME "platform-ble"
#include <g2labs-log.h>

static bool perform_gap_scan = false;

static platform_ble_scan_entry_handler_t gap_scan_entry_handler;

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t* param) {
    D("GAP_EVT, event %d\n", event);

    switch (event) {
        case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
            break;
        case ESP_GAP_BLE_SCAN_RESULT_EVT: {
            platform_ble_scan_entry_t entry;
            memcpy(entry.mac, param->scan_rst.bda, 6);
            entry.adv_data_size = param->scan_rst.adv_data_len + param->scan_rst.scan_rsp_len;
            memcpy(entry.adv_data, param->scan_rst.ble_adv, entry.adv_data_size);
            entry.rssi = param->scan_rst.rssi;
            if (gap_scan_entry_handler) {
                gap_scan_entry_handler(&entry);
            }
            break;
        }
        case ESP_GAP_BLE_SCAN_TIMEOUT_EVT:
            I("ESP_GAP_BLE_SCAN_TIMEOUT_EVT");
            break;
            // esp_ble_gap_start_scanning(UINT32_MAX);
            // case ESP_GAP_BLE_SCAN_RSP_DATA_SET_COMPLETE_EVT:
            // adv_config_done &= (~SCAN_RSP_CONFIG_FLAG);
            // if (adv_config_done == 0) {
            //     esp_ble_gap_start_advertising(&adv_params);
            // }
            // break;
            // case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
            // adv_config_done &= (~ADV_CONFIG_FLAG);
            // if (adv_config_done == 0) {
            //     esp_ble_gap_start_advertising(&adv_params);
            // }
            // break;
            // case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            // advertising start complete event to indicate advertising start successfully or failed
            // if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            //     ESP_LOGE(BLE_ANCS_TAG, "advertising start failed, error status = %x", param->adv_start_cmpl.status);
            //     break;
            // }
            // ESP_LOGI(BLE_ANCS_TAG, "advertising start success");
            // break;
            // case ESP_GAP_BLE_PASSKEY_REQ_EVT: /* passkey request event */
            // ESP_LOGI(BLE_ANCS_TAG, "ESP_GAP_BLE_PASSKEY_REQ_EVT");
            /* Call the following function to input the passkey which is displayed on the remote device */
            // esp_ble_passkey_reply(heart_rate_profile_tab[HEART_PROFILE_APP_IDX].remote_bda, true, 0x00);
            //  break;
            //  case ESP_GAP_BLE_OOB_REQ_EVT: {
            //  ESP_LOGI(BLE_ANCS_TAG, "ESP_GAP_BLE_OOB_REQ_EVT");
            //  uint8_t tk[16] = {1}; //If you paired with OOB, both devices need to use the same tk
            //  esp_ble_oob_req_reply(param->ble_security.ble_req.bd_addr, tk, sizeof(tk));
            //  break;
            //  }
            //  case ESP_GAP_BLE_NC_REQ_EVT:
            /* The app will receive this evt when the IO has DisplayYesNO capability and the peer device IO also has
        DisplayYesNo capability. show the passkey number to the user to confirm it with the number displayed by peer
        device. */
            // esp_ble_confirm_reply(param->ble_security.ble_req.bd_addr, true);
            // ESP_LOGI(BLE_ANCS_TAG, "ESP_GAP_BLE_NC_REQ_EVT, the passkey Notify number:%" PRIu32,
            // param->ble_security.key_notif.passkey); break; case ESP_GAP_BLE_SEC_REQ_EVT:
            /* send the positive(true) security response to the peer device to accept the security request.
        If not accept the security request, should send the security response with negative(false) accept value*/
            // esp_ble_gap_security_rsp(param->ble_security.ble_req.bd_addr, true);
            // break;
            // case ESP_GAP_BLE_PASSKEY_NOTIF_EVT: ///the app will receive this evt when the IO  has Output capability
            // and the peer device IO has Input capability.
            /// show the passkey number to the user to input it in the peer device.
            // ESP_LOGI(BLE_ANCS_TAG, "The passkey Notify number:%06" PRIu32, param->ble_security.key_notif.passkey);
            // break;
            // case ESP_GAP_BLE_AUTH_CMPL_EVT: {
            // esp_log_buffer_hex("addr", param->ble_security.auth_cmpl.bd_addr, ESP_BD_ADDR_LEN);
            // ESP_LOGI(BLE_ANCS_TAG, "pair status = %s", param->ble_security.auth_cmpl.success ? "success" : "fail");
            // if (!param->ble_security.auth_cmpl.success) {
            // ESP_LOGI(BLE_ANCS_TAG, "fail reason = 0x%x", param->ble_security.auth_cmpl.fail_reason);
            // }
            // break;
        // }
        // case ESP_GAP_BLE_SET_LOCAL_PRIVACY_COMPLETE_EVT:
        //     if (param->local_privacy_cmpl.status != ESP_BT_STATUS_SUCCESS) {
        //         ESP_LOGE(
        //             BLE_ANCS_TAG, "config local privacy failed, error status = %x",
        //             param->local_privacy_cmpl.status);
        //         break;
        //     }
        //     esp_err_t ret = esp_ble_gap_config_adv_data(&adv_config);
        //     if (ret) {
        //         ESP_LOGE(BLE_ANCS_TAG, "config adv data failed, error code = %x", ret);
        //     } else {
        //         adv_config_done |= ADV_CONFIG_FLAG;
        //     }
        //     ret = esp_ble_gap_config_adv_data(&scan_rsp_config);
        //     if (ret) {
        //         ESP_LOGE(BLE_ANCS_TAG, "config adv data failed, error code = %x", ret);
        //     } else {
        //         adv_config_done |= SCAN_RSP_CONFIG_FLAG;
        //     }
        //     break;
        default:
            break;
    }
}

void platform_ble_initialize(void) {
    perform_gap_scan = false;
    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    esp_err_t ret = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        E("%s init controller failed: %s", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret) {
        E("%s enable controller failed: %s", __func__, esp_err_to_name(ret));
        return;
    }

    I("%s init bluetooth", __func__);
    ret = esp_bluedroid_init();
    if (ret) {
        E("%s init bluetooth failed: %s", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_bluedroid_enable();
    if (ret) {
        E("%s enable bluetooth failed: %s", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_ble_gap_register_callback(gap_event_handler);
    if (ret) {
        E("gap register error, error code = %x", ret);
        return;
    }
}

void platform_ble_scan_start(platform_ble_scan_entry_handler_t handler) {
    gap_scan_entry_handler = handler;
    esp_ble_scan_params_t params = {
        .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
        .scan_duplicate = BLE_SCAN_DUPLICATE_DISABLE,
        .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
        .scan_interval = 0x4000,
        .scan_type = BLE_SCAN_TYPE_PASSIVE,
        .scan_window = 0x4000,
    };
    esp_err_t ret = esp_ble_gap_set_scan_params(&params);
    if (ret) {
        E("%s esp_ble_gap_set_scan_params failed: %s", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_ble_gap_start_scanning(UINT32_MAX);
    if (ret) {
        E("%s esp_ble_gap_start_scanning failed: %s", __func__, esp_err_to_name(ret));
        return;
    }
    perform_gap_scan = true;
}

void platform_ble_scan_stop(void) {
    perform_gap_scan = false;
    esp_err_t ret = esp_ble_gap_stop_scanning();
    if (ret) {
        E("%s esp_ble_gap_stop_scanning failed: %s", __func__, esp_err_to_name(ret));
        return;
    }
}