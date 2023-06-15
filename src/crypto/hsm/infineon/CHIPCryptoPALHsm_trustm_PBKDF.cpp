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

#include "CHIPCryptoPALHsm_trustm_utils.h"
#include <lib/core/CHIPEncoding.h>

#if ENABLE_HSM_PBKDF2_SHA256

namespace chip {
namespace Crypto {

static const uint8_t metadata_hmac [] = {
//Metadata tag in the data object
0x20, 0x06,
//Data object type set to PRESSEC
0xE8, 0x01, 0x21,
0xD3, 0x01, 0x00,
};

PBKDF2_sha256HSM::PBKDF2_sha256HSM()
{}
PBKDF2_sha256HSM::~PBKDF2_sha256HSM() {}

CHIP_ERROR PBKDF2_sha256HSM::pbkdf2_sha256(const uint8_t * password, size_t plen, const uint8_t * salt, size_t slen,
                                           unsigned int iteration_count, uint32_t key_length, uint8_t * output)
{
    CHIP_ERROR error = CHIP_ERROR_INTERNAL;
    optiga_lib_status_t return_status = OPTIGA_LIB_BUSY;

    VerifyOrReturnError(password != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(plen > 0, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(key_length > 0, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(output != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(slen >= kSpake2p_Min_PBKDF_Salt_Length, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(slen <= kSpake2p_Max_PBKDF_Salt_Length, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(salt != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    printf(" Trust M ---------------------> PBKDF2_sha256HSM()\n");
    // Session open
    trustm_Open();

    // Write metada for secret OID
    write_metadata(0xf1d4, metadata_hmac, sizeof(metadata_hmac));
    // Update the secret key to 0XF1D4
    write_data(0xf1d4, password, (uint16_t)plen);

    // Start HMAC operation
    return_status = OPTIGA_LIB_BUSY;

    return_status = trustm_PBKDF2_HMAC(salt, slen, iteration_count, key_length, output);

    VerifyOrExit(return_status == OPTIGA_LIB_SUCCESS, error = CHIP_ERROR_INTERNAL) ;
    error = CHIP_NO_ERROR;

    exit:
        if (error != CHIP_NO_ERROR)
        {
            trustm_close();
        }
        return error;
}

} // namespace Crypto
} // namespace chip

#endif //#if ENABLE_HSM_PBKDF2_SHA256
