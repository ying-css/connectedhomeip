/*
 *
 *    Copyright (c) 2022 Project CHIP Authors
 *    All rights reserved.
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

#ifndef _POWERCYCLE_COUNTING_H_
#define _POWERCYCLE_COUNTING_H_

#include "inttypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *                    Static Function Prototypes
 *****************************************************************************/

typedef void (*gpAppFramework_ResetExpiredHandlerType)(uint8_t);

void gpAppFramework_Reset_Init(void);
uint8_t gpAppFramework_Reset_GetResetCount(void);
void gpAppFramework_Reset_cbTriggerResetCountCompleted(void);
void gpAppFramework_SetResetExpiredHandler(gpAppFramework_ResetExpiredHandlerType handler);

#ifdef __cplusplus
}
#endif

#endif // _POWERCYCLE_COUNTING_H_
