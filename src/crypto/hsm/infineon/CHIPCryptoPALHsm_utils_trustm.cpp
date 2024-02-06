/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *      HSM based implementation of CHIP crypto primitives
 *      Based on configurations in CHIPCryptoPALHsm_config.h file,
 *      chip crypto apis use either HSM or rollback to software implementation.
 */

/* OPTIGA(TM) Trust M includes */
#include "CHIPCryptoPALHsm_utils_trustm.h"
#include "ifx_i2c_config.h"
#include "mbedtls/base64.h"
#include "optiga_crypt.h"
#include "optiga_lib_types.h"
#include "optiga_util.h"
#include "pal.h"
#include "pal_ifx_i2c_config.h"
#include "pal_os_event.h"
#include "pal_os_memory.h"
#include "pal_os_timer.h"
#include <FreeRTOS.h>

optiga_crypt_t * p_local_crypt = NULL;
optiga_util_t * p_local_util   = NULL;
static bool trustm_isOpen      = false;
#define ENABLE_HMAC_MULTI_STEP (0)
#define OPTIGA_UTIL_DER_BITSTRING_TAG (0x03)
#define OPTIGA_UTIL_DER_NUM_UNUSED_BITS (0x00)

#if ENABLE_HMAC_MULTI_STEP
#define MAX_MAC_DATA_LEN 640
#endif

// ================================================================================
// FreeRTOS Callbacks
// ================================================================================

/* This is a place from which we can poll the status of operation */

void vApplicationTickHook(void);

void vApplicationTickHook(void)
{
    pal_os_event_trigger_registered_callback();
}

#define WAIT_FOR_COMPLETION(ret)                                                                                                   \
    if (OPTIGA_LIB_SUCCESS != ret)                                                                                                 \
    {                                                                                                                              \
        break;                                                                                                                     \
    }                                                                                                                              \
    while (optiga_lib_status == OPTIGA_LIB_BUSY)                                                                                   \
    {                                                                                                                              \
        pal_os_event_trigger_registered_callback();                                                                                \
    }                                                                                                                              \
                                                                                                                                   \
    if (OPTIGA_LIB_SUCCESS != optiga_lib_status)                                                                                   \
    {                                                                                                                              \
        ret = optiga_lib_status;                                                                                                   \
        printf("Error: 0x%02X \r\n", optiga_lib_status);                                                                           \
        break;                                                                                                                     \
    }

#define CHECK_RESULT(expr)                                                                                                         \
    optiga_lib_status_t return_status = (int32_t) OPTIGA_DEVICE_ERROR;                                                             \
                                                                                                                                   \
    do                                                                                                                             \
    {                                                                                                                              \
        optiga_lib_status = OPTIGA_LIB_BUSY;                                                                                       \
        return_status     = expr;                                                                                                  \
        WAIT_FOR_COMPLETION(return_status);                                                                                        \
    } while (0);                                                                                                                   \
                                                                                                                                   \
    return return_status;

static volatile optiga_lib_status_t optiga_lib_status;

static void optiga_util_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
}

// lint --e{818} suppress "argument "context" is not used in the sample provided"
static void optiga_crypt_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
    if (NULL != context)
    {
        // callback to upper layer here
    }
}

#define DEV_ATTESTATION_CERT_ID 0xE0E3
#define PAI_CERT_ID 0xE0E8
#define CERT_DECLARATION_ID 0xF1E0

void optiga_trustm_task(void *param)
{
    (void)param;
    trustm_Open();

    uint8_t CsTest_CD_1388_0003[] = {
        0x30, 0x81, 0xE7, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, 0xA0, 0x81,\
        0xD9, 0x30, 0x81, 0xD6, 0x02, 0x01, 0x03, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48,\
        0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x43, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,\
        0x01, 0x07, 0x01, 0xA0, 0x36, 0x04, 0x34, 0x15, 0x24, 0x00, 0x01, 0x25, 0x01, 0x88, 0x13, 0x36,\
        0x02, 0x04, 0x03, 0x18, 0x24, 0x03, 0x0A, 0x2C, 0x04, 0x13, 0x5A, 0x49, 0x47, 0x32, 0x30, 0x31,\
        0x34, 0x31, 0x5A, 0x42, 0x33, 0x33, 0x30, 0x30, 0x30, 0x31, 0x2D, 0x32, 0x34, 0x24, 0x05, 0x00,\
        0x24, 0x06, 0x00, 0x25, 0x07, 0x76, 0x98, 0x24, 0x08, 0x00, 0x18, 0x31, 0x7D, 0x30, 0x7B, 0x02,\
        0x01, 0x03, 0x80, 0x14, 0x62, 0xFA, 0x82, 0x33, 0x59, 0xAC, 0xFA, 0xA9, 0x96, 0x3E, 0x1C, 0xFA,\
        0x14, 0x0A, 0xDD, 0xF5, 0x04, 0xF3, 0x71, 0x60, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,\
        0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03,\
        0x02, 0x04, 0x47, 0x30, 0x45, 0x02, 0x20, 0x2D, 0x5F, 0xE6, 0xB1, 0xF0, 0xBB, 0x52, 0xB5, 0x02,\
        0x6B, 0x42, 0x74, 0xFB, 0xE4, 0xB0, 0xD4, 0x07, 0x10, 0x84, 0x4B, 0x08, 0xDF, 0xD8, 0xFF, 0x33,\
        0xAB, 0x6F, 0x76, 0xBB, 0x0D, 0xDC, 0x5E, 0x02, 0x21, 0x00, 0x84, 0xD1, 0xB9, 0x06, 0xAD, 0x7D,\
        0x0B, 0x8D, 0x26, 0x21, 0x76, 0xAD, 0x34, 0x80, 0x3E, 0x9D, 0xB6, 0x16, 0xA9, 0xA9, 0x5D, 0x07,\
        0x7A, 0x4E, 0xD1, 0x69, 0x1E, 0xCA, 0x3F, 0x77, 0x95, 0x44
       };
    uint8_t sTestCert_PAI_1388_0003_Cert_Array[] = {
        0x30, 0x82, 0x01, 0xe5, 0x30, 0x82, 0x01, 0x8c, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x5a,\
        0xaf, 0xf5, 0x30, 0x31, 0x38, 0xd5, 0x83, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,\
        0x04, 0x03, 0x02, 0x30, 0x39, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x18,\
        0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f, 0x6e, 0x20, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20,\
        0x54, 0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x41, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06,\
        0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x31, 0x33, 0x38, 0x38, 0x30, 0x20,
        0x17, 0x0d, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18,\
        0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,\
        0x30, 0x4f, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x18, 0x49, 0x6e, 0x66,\
        0x69, 0x6e, 0x65, 0x6f, 0x6e, 0x20, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73,\
        0x74, 0x20, 0x50, 0x41, 0x49, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,\
        0x82, 0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x31, 0x33, 0x38, 0x38, 0x31, 0x14, 0x30, 0x12, 0x06,\
        0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x02, 0x0c, 0x04, 0x30, 0x30, 0x30,\
        0x33, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,\
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xd4, 0xb8, 0x24, 0x46,\
        0xb9, 0xe1, 0x2d, 0x42, 0xe3, 0x90, 0xec, 0x6b, 0x67, 0x82, 0x98, 0x25, 0x3c, 0xfe, 0x29, 0x6b,\
        0x7b, 0x8e, 0xc4, 0x90, 0x7b, 0xc4, 0xbd, 0xa6, 0xf0, 0xcc, 0x48, 0x8e, 0x18, 0xbb, 0x5e, 0x93,\
        0xb3, 0x4b, 0x2a, 0xa4, 0x48, 0xb5, 0x95, 0x6b, 0x89, 0xac, 0xfe, 0xf3, 0x87, 0x77, 0x58, 0xd5,\
        0x5b, 0x03, 0x5a, 0x2e, 0xe5, 0x16, 0x03, 0x28, 0x79, 0xd1, 0x3e, 0x80, 0xa3, 0x66, 0x30, 0x64,\
        0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01,\
        0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,\
        0x03, 0x02, 0x01, 0x06, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xe0,\
        0x87, 0xac, 0x9b, 0x23, 0x03, 0xa7, 0x3b, 0x5e, 0x81, 0xd4, 0x12, 0xb8, 0x1c, 0x4d, 0x15, 0xbe,\
        0xbc, 0xd1, 0xd7, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,\
        0xec, 0xa2, 0x3a, 0xf2, 0x41, 0xcb, 0x7a, 0xa4, 0x4e, 0xb0, 0x7b, 0x3e, 0xfa, 0x97, 0xa7, 0xd4,\
        0xd5, 0x08, 0x43, 0x7b, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,\
        0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x7f, 0x97, 0x9c, 0xba, 0x4f, 0xb9, 0x67, 0xd7, 0x48,\
        0x84, 0x37, 0xe5, 0xf0, 0x51, 0x63, 0x20, 0x95, 0x07, 0x4d, 0x03, 0xaa, 0xb7, 0x10, 0x8c, 0x0f,\
        0x95, 0x88, 0x73, 0x9d, 0xae, 0xd2, 0x1f, 0x02, 0x20, 0x1b, 0xe0, 0x46, 0x38, 0x21, 0x2a, 0xb1,\
        0xec, 0xe5, 0x7d, 0xf8, 0x52, 0xf3, 0xa5, 0x68, 0xae, 0xb2, 0x0c, 0x01, 0x68, 0xf2, 0x5d, 0xa6,\
        0xe2, 0x66, 0xfe, 0x80, 0xbe, 0x30, 0x7a, 0x70, 0x65,
    }; 
#if 1
    uint8_t CsTestCert_DAC_1388_0003_3840[] = {
       0x30, 0x82, 0x02, 0x07, 0x30, 0x82, 0x01, 0xAC, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x39,
       0x0E, 0x9F, 0x6F, 0x62, 0x9D, 0x9B, 0x34, 0xAE, 0xA4, 0xEF, 0x9E, 0xDD, 0xDB, 0x76, 0x56, 0xC8,
       0xAE, 0xAD, 0x09, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
       0x4F, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x18, 0x49, 0x6E, 0x66, 0x69,
       0x6E, 0x65, 0x6F, 0x6E, 0x20, 0x4D, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74,
       0x20, 0x50, 0x41, 0x49, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82,
       0xA2, 0x7C, 0x02, 0x01, 0x0C, 0x04, 0x31, 0x33, 0x38, 0x38, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0A,
       0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02, 0x02, 0x0C, 0x04, 0x30, 0x30, 0x30, 0x33,
       0x30, 0x20, 0x17, 0x0D, 0x32, 0x34, 0x30, 0x32, 0x30, 0x35, 0x30, 0x31, 0x30, 0x37, 0x35, 0x34,
       0x5A, 0x18, 0x0F, 0x32, 0x30, 0x35, 0x31, 0x30, 0x36, 0x32, 0x33, 0x30, 0x31, 0x30, 0x37, 0x35,
       0x34, 0x5A, 0x30, 0x53, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1C, 0x49,
       0x6E, 0x66, 0x69, 0x6E, 0x65, 0x6F, 0x6E, 0x20, 0x4D, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x44,
       0x65, 0x76, 0x20, 0x44, 0x41, 0x43, 0x20, 0x30, 0x30, 0x30, 0x31, 0x31, 0x14, 0x30, 0x12, 0x06,
       0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02, 0x01, 0x0C, 0x04, 0x31, 0x33, 0x38,
       0x38, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02,
       0x02, 0x0C, 0x04, 0x30, 0x30, 0x30, 0x33, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
       0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42,
       0x00, 0x04, 0x42, 0x8B, 0xA6, 0x61, 0xAC, 0xEB, 0x54, 0x57, 0x89, 0x28, 0xFD, 0xB7, 0x79, 0x8A,
       0x28, 0x6A, 0x98, 0x7D, 0xDE, 0x70, 0x27, 0x3D, 0x80, 0x34, 0x31, 0x3C, 0x6A, 0x93, 0xFC, 0xB1,
       0x9C, 0xE2, 0xA7, 0xB8, 0x05, 0x65, 0x61, 0xE4, 0x8D, 0x30, 0x5A, 0x41, 0x43, 0x29, 0x09, 0xC0,
       0x60, 0x70, 0xC8, 0x62, 0x1E, 0x6A, 0x51, 0xC7, 0x90, 0x9E, 0x37, 0x9E, 0xE4, 0xAD, 0xED, 0x1C,
       0x3E, 0x75, 0xA3, 0x60, 0x30, 0x5E, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30,
       0x16, 0x80, 0x14, 0xE0, 0x87, 0xAC, 0x9B, 0x23, 0x03, 0xA7, 0x3B, 0x5E, 0x81, 0xD4, 0x12, 0xB8,
       0x1C, 0x4D, 0x15, 0xBE, 0xBC, 0xD1, 0xD7, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01,
       0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04,
       0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14,
       0x8F, 0x54, 0xFF, 0x36, 0x3B, 0x6F, 0xA3, 0xCE, 0x4A, 0x84, 0x7F, 0xE4, 0x5A, 0xA1, 0x74, 0xD2,
       0x3B, 0x6A, 0xFD, 0xA7, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
       0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xE8, 0x4A, 0xC0, 0xAF, 0x5F, 0x85, 0x50, 0x0E,
       0xB2, 0x7C, 0x5A, 0x28, 0xE4, 0x62, 0x12, 0x8F, 0x6A, 0x09, 0x8E, 0x80, 0x48, 0x82, 0x1F, 0x2C,
       0x5D, 0x92, 0xD3, 0x86, 0x6B, 0x92, 0x16, 0xA4, 0x02, 0x21, 0x00, 0x80, 0xFA, 0x7B, 0x03, 0x76,
       0xD0, 0x0B, 0x02, 0xC0, 0xAD, 0xD9, 0x70, 0xCB, 0x2E, 0x64, 0x65, 0x36, 0x0F, 0x23, 0x80, 0xBB,
       0xC6, 0x87, 0xF2, 0xE5, 0x00, 0x24, 0x71, 0x2D, 0x8E, 0x3F, 0xAA
    };
#endif
#if 0
    uint8_t CsTestCert_DAC_1388_0003_DAC1[] = {
        0x30, 0x82, 0x02, 0x03, 0x30, 0x82, 0x01, 0xAA, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x39

    };
#endif
#if 0
    uint8_t CsTestCert_DAC_1388_0003_DAC2[] = {
        0x30, 0x82, 0x01, 0xFB, 0x30, 0x82, 0x01, 0xA1, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x39
    };
#endif
    // Write CD
    printf("Writing CD\n");
    write_data(CERT_DECLARATION_ID, CsTest_CD_1388_0003, sizeof(CsTest_CD_1388_0003));

    //Read CD
    // read_data(CERT_DECLARATION_ID);

    // Write PAI
    printf("Writing PAI\n");
    write_data(PAI_CERT_ID, sTestCert_PAI_1388_0003_Cert_Array, sizeof(sTestCert_PAI_1388_0003_Cert_Array));

    // read_data(PAI_CERT_ID);

    // Write DAC1
    printf("Writitng DAC1\n");

    write_data(DEV_ATTESTATION_CERT_ID, CsTestCert_DAC_1388_0003_3840, sizeof(CsTestCert_DAC_1388_0003_3840));
    // write_data(DEV_ATTESTATION_CERT_ID, CsTestCert_DAC_1388_0003_DAC1, sizeof(CsTestCert_DAC_1388_0003_DAC1));

    //Wite DAC2
    // write_data(DEV_ATTESTATION_CERT_ID, CsTestCert_DAC_1388_0003_DAC2, sizeof(CsTestCert_DAC_1388_0003_DAC2));

    //Read DAC
    // read_data(DEV_ATTESTATION_CERT_ID);

    for (;;)
    {

    }
    vTaskDelay(pdMS_TO_TICKS(500));
}
/* Open session to trustm */
/**********************************************************************
 * trustm_Open()
 **********************************************************************/
void trustm_Open(void)
{
    if (!trustm_isOpen)
    {
        optiga_lib_status_t return_status;
        do
        {
            /**
             * 1. Create OPTIGA Crypt Instance
             */
            p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
            if (NULL == p_local_crypt)
            {
                break;
            }
            // printf("trustm created crypt Instance \r\n");
            /**
             * 1. Create OPTIGA Util Instance
             */
            p_local_util = optiga_util_create(0, optiga_util_callback, NULL);
            if (NULL == p_local_util)
            {
                break;
            }
            // printf("trustm created util Instance \r\n");
            /**
             * Open the application on OPTIGA which is a precondition to perform any other operations
             * using optiga_util_open_application
             */
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status     = optiga_util_open_application(p_local_util, 0); // skip restore
            while (optiga_lib_status == OPTIGA_LIB_BUSY)
                ;

            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                // optiga_util_open_application api returns error !!!
                printf("optiga_util_open_application api returns error !!!\n");
                break;
            }

            while (optiga_lib_status == OPTIGA_LIB_BUSY)
                ;
            if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
            {
                // optiga_util_open_application failed
                printf("optiga_util_open_application failed\n");
                break;
            }

            // printf("trustm open application successful \r\n");

        } while (0);

        // p_local_util and p_local_crypt instance can be destroyed
        // if no close_application w.r.t hibernate is required to be performed
        if (p_local_util || p_local_crypt)
        {
            optiga_util_destroy(p_local_util);
            optiga_crypt_destroy(p_local_crypt);
        }
        trustm_isOpen = true;
    }
}

void trustm_close(void)
{
    optiga_lib_status_t return_status = OPTIGA_DEVICE_ERROR;

    do
    {
        /**
         * Close the application on OPTIGA after all the operations are executed
         * using optiga_util_close_application
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status     = optiga_util_close_application(p_local_util, 0);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            pal_os_event_trigger_registered_callback();
        }

        // destroy util and crypt instances
        optiga_util_destroy(p_local_util);
        optiga_crypt_destroy(p_local_crypt);
        pal_os_event_destroy(NULL);

        return_status = OPTIGA_LIB_SUCCESS;
    } while (0);
}

void read_certificate_from_optiga(uint16_t optiga_oid, char * cert_pem, uint16_t * cert_pem_length)
{
    size_t ifx_cert_b64_len = 0;
    uint8_t ifx_cert_b64_temp[1200];
    uint16_t offset_to_write = 0, offset_to_read = 0;
    uint16_t size_to_copy = 0;
    optiga_lib_status_t return_status;

    optiga_util_t * me_util = NULL;
    uint8_t ifx_cert_hex[1024];
    uint16_t ifx_cert_hex_len = sizeof(ifx_cert_hex);

    do
    {
        // Create an instance of optiga_util to read the certificate from OPTIGA.
        me_util = optiga_util_create(0, optiga_util_callback, NULL);
        if (!me_util)
        {
            optiga_lib_print_message("optiga_util_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status     = optiga_util_read_data(me_util, optiga_oid, 0, ifx_cert_hex, &ifx_cert_hex_len);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_util_read_data api returns error !!!
            optiga_lib_print_message("optiga_util_read_data api returns error !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            // optiga_util_read_data failed
            optiga_lib_print_message("optiga_util_read_data failed", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        // convert to PEM format
        // If the first byte is TLS Identity Tag, than we need to skip 9 first bytes
        offset_to_read = ifx_cert_hex[0] == 0xc0 ? 9 : 0;
        mbedtls_base64_encode((unsigned char *) ifx_cert_b64_temp, sizeof(ifx_cert_b64_temp), &ifx_cert_b64_len,
                              ifx_cert_hex + offset_to_read, ifx_cert_hex_len - offset_to_read);

        memcpy(cert_pem, "-----BEGIN CERTIFICATE-----\n", 28);
        offset_to_write += 28;

        // Properly copy certificate and format it as pkcs expects
        for (offset_to_read = 0; offset_to_read < (uint16_t) ifx_cert_b64_len;)
        {
            // The last block of data usually is less than 64, thus we need to find the leftover
            if ((offset_to_read + 64) >= (uint16_t) ifx_cert_b64_len)
                size_to_copy = (uint16_t) ifx_cert_b64_len - offset_to_read;
            else
                size_to_copy = 64;
            memcpy(cert_pem + offset_to_write, ifx_cert_b64_temp + offset_to_read, size_to_copy);
            offset_to_write += size_to_copy;
            offset_to_read += size_to_copy;
            cert_pem[offset_to_write] = '\n';
            offset_to_write++;
        }

        memcpy(cert_pem + offset_to_write, "-----END CERTIFICATE-----\n\0", 27);

        *cert_pem_length = offset_to_write + 27;

    } while (0);

    // me_util instance to be destroyed
    if (me_util)
    {
        optiga_util_destroy(me_util);
    }
}

void read_data(uint16_t optiga_oid)
{
    optiga_lib_status_t return_status;

    optiga_util_t * me_util = NULL;
    uint8_t ifx_cert_hex[1024];
    uint16_t ifx_cert_hex_len = sizeof(ifx_cert_hex);

    do
    {
        // Create an instance of optiga_util to read the certificate from OPTIGA.
        me_util = optiga_util_create(0, optiga_util_callback, NULL);
        if (!me_util)
        {
            optiga_lib_print_message("optiga_util_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status     = optiga_util_read_data(me_util, optiga_oid, 0, ifx_cert_hex, &ifx_cert_hex_len);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_util_read_data api returns error !!!
            optiga_lib_print_message("optiga_util_read_data api returns error !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            // optiga_util_read_data failed
            optiga_lib_print_message("optiga_util_read_data failed", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        printf("Raw bytes - \n");
        for (int i = 0; i < ifx_cert_hex_len; i++)
        {
            if (i != 0 && i % 16 == 0 )
            {
                printf(" 0x%02x,\n", ifx_cert_hex[i]);
            }
            else
            {
                printf(" 0x%02x, ", ifx_cert_hex[i] );
            }
        }

    } while (0);

    // me_util instance to be destroyed
    if (me_util)
    {
        optiga_util_destroy(me_util);
    }
}
void write_data(uint16_t optiga_oid, const uint8_t * p_data, uint16_t length)
{
    optiga_util_t * me_util = NULL;
    optiga_lib_status_t return_status;

    do
    {
        // Create an instance of optiga_util to open the application on OPTIGA.
        me_util = optiga_util_create(0, optiga_util_callback, NULL);
        if (!me_util)
        {
            optiga_lib_print_message("optiga_util_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status     = optiga_util_write_data(me_util, optiga_oid, OPTIGA_UTIL_ERASE_AND_WRITE, 0, p_data, length);
        {
            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                optiga_lib_print_message("optiga_util_wirte_data api returns error !!!", OPTIGA_UTIL_SERVICE,
                                         OPTIGA_UTIL_SERVICE_COLOR);
                break;
            }

            while (OPTIGA_LIB_BUSY == optiga_lib_status)
            {
                // Wait until the optiga_util_write_data operation is completed
            }

            if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
            {
                optiga_lib_print_message("optiga_util_write_data failed", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
                return_status = optiga_lib_status;
                break;
            }
            else
            {
                optiga_lib_print_message("optiga_util_write_data successful", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            }
        }
    } while (0);

    // me_util instance can be destroyed
    // if no close_application w.r.t hibernate is required to be performed
    if (me_util)
    {
        optiga_util_destroy(me_util);
    }
}

void write_metadata(uint16_t optiga_oid, const uint8_t * p_data, uint8_t length)
{
    optiga_util_t * me_util = NULL;
    optiga_lib_status_t return_status;

    do
    {
        // Create an instance of optiga_util to open the application on OPTIGA.
        me_util = optiga_util_create(0, optiga_util_callback, NULL);
        if (!me_util)
        {
            optiga_lib_print_message("optiga_util_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status     = optiga_util_write_metadata(me_util, optiga_oid, p_data, length);
        {
            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                optiga_lib_print_message("optiga_util_wirte_data api returns error !!!", OPTIGA_UTIL_SERVICE,
                                         OPTIGA_UTIL_SERVICE_COLOR);
                break;
            }

            while (OPTIGA_LIB_BUSY == optiga_lib_status)
            {
                // Wait until the optiga_util_write_metadata operation is completed
            }

            if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
            {
                optiga_lib_print_message("optiga_util_write_metadata failed", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
                return_status = optiga_lib_status;
                break;
            }
            else
            {
                optiga_lib_print_message("optiga_util_write_metadata successful", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            }
        }
    } while (0);

    // me_util instance can be destroyed
    // if no close_application w.r.t hibernate is required to be performed
    if (me_util)
    {
        optiga_util_destroy(me_util);
    }
}

optiga_lib_status_t deriveKey_HKDF(const uint8_t * salt, uint16_t salt_length, const uint8_t * info, uint16_t info_length,
                                   uint16_t derived_key_length, bool_t export_to_host, uint8_t * derived_key)
{
    optiga_lib_status_t return_status;

    do
    {
        // Create an instance of optiga_crypt_t
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == p_local_crypt)
        {
            optiga_lib_print_message("optiga_crypt_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status     = optiga_crypt_hkdf(p_local_crypt, OPTIGA_HKDF_SHA_256, TRUSTM_HKDF_OID_KEY, /* Input secret OID */
                                          salt, salt_length, info, info_length, derived_key_length, TRUE, derived_key);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_crypt_hkdf api returns error !!!
            optiga_lib_print_message("optiga_crypt_hkdf api returns error !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            // optiga_crypt_hkdf failed
            optiga_lib_print_message("optiga_crypt_hkdf failed", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
    } while (0);

    if (p_local_crypt)
    {
        optiga_crypt_destroy(p_local_crypt);
    }
    return return_status;
}

optiga_lib_status_t hmac_sha256(optiga_hmac_type_t type, const uint8_t * input_data, uint32_t input_data_length, uint8_t * mac,
                                uint32_t * mac_length)
{
    optiga_lib_status_t return_status;

    do
    {
        // Create an instance of optiga_crypt_t
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == p_local_crypt)
        {
            optiga_lib_print_message("optiga_crypt_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        return_status = OPTIGA_LIB_BUSY;
#if ENABLE_HMAC_MULTI_STEP
        // If the size is less than the max length supported
        if (input_data_length <= MAX_MAC_DATA_LEN)
        {
            return_status =
                optiga_crypt_hmac(p_local_crypt, type, TRUSTM_HMAC_OID_KEY, input_data, input_data_length, mac, mac_length);
            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                // optiga_crypt_hmac api returns error !!!
                optiga_lib_print_message("optiga_crypt_hmac api returns error !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
                break;
            }
        }
        else
        {
            // Calculate HMAC in multiple steps
            uint32_t dataLenTemp  = 0;
            uint32_t remainingLen = input_data_length;
            // Start the HMAC Operation
            return_status = optiga_crypt_hmac_start(p_local_crypt, type, TRUSTM_HMAC_OID_KEY, input_data, MAX_MAC_DATA_LEN);

            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                // optiga_crypt_hmac_start api returns error !!!
                optiga_lib_print_message("optiga_crypt_hmac_start api returns error !!!", OPTIGA_UTIL_SERVICE,
                                         OPTIGA_UTIL_SERVICE_COLOR);
                break;
            }
            remainingLen = input_data_length - MAX_MAC_DATA_LEN;

            while (remainingLen > 0)
            {
                dataLenTemp = (remainingLen > MAX_MAC_DATA_LEN) ? MAX_MAC_DATA_LEN : remainingLen;

                if (remainingLen > MAX_MAC_DATA_LEN)
                {
                    return_status = OPTIGA_LIB_BUSY;
                    // printf("HMAC Update\n");
                    // Continue HMAC operation on input data
                    return_status =
                        optiga_crypt_hmac_update(p_local_crypt, (input_data + (input_data_length - remainingLen)), dataLenTemp);
                    remainingLen = remainingLen - dataLenTemp;

                    if (OPTIGA_LIB_SUCCESS != return_status)
                    {
                        // optiga_crypt_hmac_update api returns error !!!
                        optiga_lib_print_message("optiga_crypt_hmac_update api returns error !!!", OPTIGA_UTIL_SERVICE,
                                                 OPTIGA_UTIL_SERVICE_COLOR);
                        break;
                    }
                }
                else
                {
                    // End HMAC sequence and return the MAC generated
                    // printf("HMAC Finalize\n");
                    return_status = OPTIGA_LIB_BUSY;
                    return_status = optiga_crypt_hmac_finalize(p_local_crypt, (input_data + (input_data_length - remainingLen)),
                                                               dataLenTemp, mac, mac_length);

                    if (OPTIGA_LIB_SUCCESS != return_status)
                    {
                        // optiga_crypt_hmac_finalize api returns error !!!
                        optiga_lib_print_message("optiga_crypt_hmac_finalize api returns error !!!", OPTIGA_UTIL_SERVICE,
                                                 OPTIGA_UTIL_SERVICE_COLOR);
                        break;
                    }
                }
            }
        }
#else

        return_status = optiga_crypt_hmac(p_local_crypt, type, TRUSTM_HMAC_OID_KEY, input_data, input_data_length, mac, mac_length);
        // printf("Output Length %ld Input Length %ld \n", *mac_length, input_data_length);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_crypt_hmac api returns error !!!
            optiga_lib_print_message("optiga_crypt_hmac api returns error !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            // optiga_crypt_hkdf failed
            optiga_lib_print_message("optiga_crypt_hkdf failed", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
#endif
    } while (0);

    if (p_local_crypt)
    {
        optiga_crypt_destroy(p_local_crypt);
    }
    return return_status;
}

optiga_lib_status_t trustm_ecc_keygen(uint16_t optiga_key_id, uint8_t key_type, optiga_ecc_curve_t curve_id, uint8_t * pubkey,
                                      uint16_t pubkey_length)
{
    optiga_lib_status_t return_status;
    uint8_t header256[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
                            0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    uint16_t i;
    for (i = 0; i < sizeof(header256); i++)
    {
        pubkey[i] = header256[i];
    }
    do
    {
        // Create an instance of optiga_crypt_t
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == p_local_crypt)
        {
            optiga_lib_print_message("optiga_crypt_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_ecc_generate_keypair(p_local_crypt, curve_id, key_type, FALSE, &optiga_key_id, (pubkey + i),
                                                          &pubkey_length);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_crypt_ecc_generate_keypair api returns error !!!
            optiga_lib_print_message("optiga_crypt_ecc_generate_keypair api returns error !!!", OPTIGA_UTIL_SERVICE,
                                     OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;

    } while (0);

    if (p_local_crypt)
    {
        optiga_crypt_destroy(p_local_crypt);
    }
    return return_status;
}
void trustmGetKey(uint16_t optiga_oid, uint8_t * pubkey, uint16_t * pubkeyLen)
{
    optiga_lib_status_t return_status;
    uint16_t offset = 0;
    do
    {
        // Create an instance of optiga_crypt_t
        p_local_util = optiga_util_create(0, optiga_util_callback, NULL);
        if (NULL == p_local_util)
        {
            optiga_lib_print_message("optiga_util_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status     = optiga_util_read_data(p_local_util, optiga_oid, offset, pubkey, pubkeyLen);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_util_read_pubkey api returns error !!!
            optiga_lib_print_message("optiga_util_read_pubkey returns error !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;

    } while (0);

    if (p_local_util)
    {
        optiga_util_destroy(p_local_util);
    }
}
optiga_lib_status_t trustm_hash(uint8_t * msg, uint16_t msg_length, uint8_t * digest, uint8_t digest_length)
{
    optiga_lib_status_t return_status;
    hash_data_from_host_t hash_data_host;
    do
    {
        // Create an instance of optiga_crypt_t
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == p_local_crypt)
        {
            optiga_lib_print_message("optiga_crypt_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        hash_data_host.buffer = msg;
        hash_data_host.length = msg_length;
        optiga_lib_status     = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_hash(p_local_crypt, OPTIGA_HASH_TYPE_SHA_256, OPTIGA_CRYPT_HOST_DATA, &hash_data_host, digest);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_crypt_ecdsa_sign api returns error !!!
            optiga_lib_print_message("optiga_crypt_hash api returns error !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;
    } while (0);

    if (p_local_crypt)
    {
        optiga_crypt_destroy(p_local_crypt);
    }
    return return_status;
}
optiga_lib_status_t trustm_ecdsa_sign(optiga_key_id_t optiga_key_id, uint8_t * digest, uint8_t digest_length, uint8_t * signature,
                                      uint16_t * signature_length)
{
    optiga_lib_status_t return_status;
    int i;
    do
    {
        // Create an instance of optiga_crypt_t
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == p_local_crypt)
        {
            optiga_lib_print_message("optiga_crypt_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_ecdsa_sign(p_local_crypt, digest, digest_length, optiga_key_id, signature, signature_length);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_crypt_ecdsa_sign api returns error !!!
            optiga_lib_print_message("optiga_crypt_ecdsa_sign api returns error !!!", OPTIGA_UTIL_SERVICE,
                                     OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;

        for (i = (*signature_length - 1); i >= 0; i--)
        {
            signature[i + 2] = signature[i];
        }

        signature[0]      = 0x30;                         // Insert SEQUENCE
        signature[1]      = (uint8_t)(*signature_length); // insert length
        *signature_length = *signature_length + 2;

    } while (0);

    if (p_local_crypt)
    {
        optiga_crypt_destroy(p_local_crypt);
    }
    return return_status;
}
void ecc_pub_key_bit(uint8_t * q_buffer, uint8_t q_length, uint8_t * pub_key_buffer, uint16_t * pub_key_length)
{
#define OPTIGA_UTIL_ECC_DER_ADDITIONAL_LENGTH (0x02)

    uint16_t index = 0;

    pub_key_buffer[index++] = OPTIGA_UTIL_DER_BITSTRING_TAG;
    pub_key_buffer[index++] = q_length + OPTIGA_UTIL_ECC_DER_ADDITIONAL_LENGTH;
    pub_key_buffer[index++] = OPTIGA_UTIL_DER_NUM_UNUSED_BITS;
    // Compression format. Supports only 04 [uncompressed]
    pub_key_buffer[index++] = 0x04;

    pal_os_memcpy(&pub_key_buffer[index], q_buffer, q_length);
    index += q_length;

    *pub_key_length = index;

#undef OPTIGA_UTIL_ECC_DER_ADDITIONAL_LENGTH
}
optiga_lib_status_t trustm_ecdsa_verify(uint8_t * digest, uint8_t digest_length, uint8_t * signature, uint16_t signature_length,
                                        uint8_t * ecc_pubkey, uint8_t ecc_pubkey_length)
{
    optiga_lib_status_t return_status;
    uint8_t ecc_public_key[70] = { 0x00 };
    uint16_t i;
    uint16_t ecc_public_key_length = 0;
    ecc_pub_key_bit(ecc_pubkey, ecc_pubkey_length, ecc_public_key, &ecc_public_key_length);

    public_key_from_host_t public_key_details = { ecc_public_key, ecc_public_key_length, (uint8_t) OPTIGA_ECC_CURVE_NIST_P_256 };
    do
    {
        // Create an instance of optiga_crypt_t
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);

        if (NULL == p_local_crypt)
        {
            optiga_lib_print_message("optiga_crypt_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        signature_length = signature[1];
        for (i = 0; i < signature_length; i++)
        {
            signature[i] = signature[i + 2];
        }
        return_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_ecdsa_verify(p_local_crypt, digest, digest_length, signature, signature_length,
                                                  OPTIGA_CRYPT_HOST_DATA, &public_key_details);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_crypt_ecdsa_verify api returns error !!!
            optiga_lib_print_message("optiga_crypt_ecdsa_verify api returns error !!!", OPTIGA_UTIL_SERVICE,
                                     OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;
    } while (0);

    if (p_local_crypt)
    {
        optiga_crypt_destroy(p_local_crypt);
    }
    return return_status;
}

CHIP_ERROR trustmGetCertificate(uint16_t optiga_oid, uint8_t * buf, uint16_t * buflen)
{
    optiga_lib_status_t return_status;
    VerifyOrReturnError(buf != nullptr, CHIP_ERROR_INTERNAL);
    VerifyOrReturnError(buflen != nullptr, CHIP_ERROR_INTERNAL);

    uint8_t ifx_cert_hex[1024];
    uint16_t ifx_cert_hex_len = sizeof(ifx_cert_hex);

    trustm_Open();
    do
    {
        // Create an instance of optiga_util to read the certificate from OPTIGA.
        p_local_util = optiga_util_create(0, optiga_util_callback, NULL);
        if (!p_local_util)
        {
            optiga_lib_print_message("optiga_util_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status     = optiga_util_read_data(p_local_util, optiga_oid, 0, ifx_cert_hex, &ifx_cert_hex_len);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_util_read_data api returns error !!!
            optiga_lib_print_message("optiga_util_read_data api returns error !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            // optiga_util_read_data failed
            optiga_lib_print_message("optiga_util_read_data failed", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        memcpy(buf, ifx_cert_hex, ifx_cert_hex_len);
        *buflen = ifx_cert_hex_len;
        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            // optiga_util_read_data failed
            optiga_lib_print_message("optiga_util_read_data failed", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
    } while (0);

    if (p_local_util)
    {
        optiga_util_destroy(p_local_util);
    }
    return CHIP_NO_ERROR;
}
optiga_lib_status_t trustm_ecdh_derive_secret(optiga_key_id_t optiga_key_id, uint8_t * public_key, uint16_t public_key_length,
                                              uint8_t * shared_secret, uint8_t shared_secret_length)
{
    optiga_lib_status_t return_status;
    static public_key_from_host_t public_key_details = {
        (uint8_t *) public_key,
        public_key_length,
        (uint8_t) OPTIGA_ECC_CURVE_NIST_P_256,
    };
    do
    {
        // Create an instance of optiga_crypt_t
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);

        if (NULL == p_local_crypt)
        {
            optiga_lib_print_message("optiga_crypt_create failed !!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        return_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_ecdh(p_local_crypt, optiga_key_id, &public_key_details, TRUE, shared_secret);
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            // optiga_crypt_ecdsa_verify api returns error !!!
            optiga_lib_print_message("optiga_crypt_ecdsa_verify api returns error !!!", OPTIGA_UTIL_SERVICE,
                                     OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;
    } while (0);

    if (p_local_crypt)
    {
        optiga_crypt_destroy(p_local_crypt);
    }
    return return_status;
}

optiga_lib_status_t trustm_PBKDF2_HMAC(const unsigned char * salt, size_t slen, unsigned int iteration_count, uint32_t key_length,
                                       unsigned char * output)
{
    optiga_lib_status_t return_status;
    uint8_t md1[32];
    uint32_t md1_len = sizeof(md1);
    uint8_t work[32];
    uint32_t work_len = sizeof(work);

    unsigned char * out_p = output;
    do
    {
        // Create an instance of optiga_crypt_t
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == p_local_crypt)
        {
            optiga_lib_print_message("optiga_crypt_create failed!!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }

        // Calculate U1, U1 ends up in work
        return_status =
            optiga_crypt_hmac(p_local_crypt, OPTIGA_HMAC_SHA_256, TRUSTM_HMAC_OID_KEY, salt, (uint32_t) slen, work, &work_len);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            optiga_lib_print_message("optiga_crypt_hmac api returns error!!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
            break;
        }
        return_status = OPTIGA_LIB_BUSY;
        memcpy(md1, work, md1_len);
        for (unsigned int i = 1; i < iteration_count; i++)
        {
            // Calculated subsequent U, which ends up in md1
            return_status = optiga_crypt_hmac(p_local_crypt, OPTIGA_HMAC_SHA_256, TRUSTM_HMAC_OID_KEY, md1, md1_len, md1, &md1_len);

            if (OPTIGA_LIB_SUCCESS != return_status)
            {
                optiga_lib_print_message("optiga_crypt_hmac api returns error!!!", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);
                break;
            }
            return_status = OPTIGA_LIB_BUSY;

            // U1 xor U2
            for (int j = 0; j < (int) md1_len; j++)
            {
                work[j] ^= md1[j];
            }
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
            ;

        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)

        {

            // optiga_crypt_hkdf failed

            optiga_lib_print_message("optiga_crypt_pbkdf_hmac failed failed", OPTIGA_UTIL_SERVICE, OPTIGA_UTIL_SERVICE_COLOR);

            break;
        }
        memcpy(out_p, work, key_length);
    } while (0);

    if (p_local_crypt)
    {
        optiga_crypt_destroy(p_local_crypt);
    }
    return return_status;
}