/**
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
 * @file API declarations for time sync cluster.
 */

#pragma once

#include "TimeSyncDataProvider.h"

#include <app/server/Server.h>
#include <app/util/af-types.h>
#include <app/util/config.h>
#include <lib/core/TLV.h>

#include <app-common/zap-generated/cluster-objects.h>
#include <lib/support/Span.h>

namespace chip {
namespace app {
namespace Clusters {
namespace TimeSynchronization {

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::TimeSynchronization;
using namespace chip::app::Clusters::TimeSynchronization::Attributes;
using chip::TimeSyncDataProvider;
using chip::Protocols::InteractionModel::Status;

class TimeSynchronizationServer
{
    struct timeZoneName
    {
        char name[64];
    };

public:
    void Init();

    static TimeSynchronizationServer & Instance(void);

    TimeSyncDataProvider GetDataProvider(void) { return mTimeSyncDataProvider; }

    CHIP_ERROR SetTrustedTimeSource(DataModel::Nullable<TimeSynchronization::Structs::TrustedTimeSourceStruct::Type> tts)
    {
        if (!tts.IsNull())
        {
            mTrustedTimeSource.SetNonNull(tts.Value());
            mTimeSyncDataProvider.StoreTrustedTimeSource(tts.Value());
        }
        else
        {
            mTrustedTimeSource.SetNull();
            mTimeSyncDataProvider.ClearTrustedTimeSource();
        }

        return CHIP_NO_ERROR;
    }

    CHIP_ERROR SetDefaultNtp(DataModel::Nullable<chip::MutableByteSpan> dntp)
    {
        if (!dntp.IsNull())
        {
            memcpy(mDefaultNtpBuf, dntp.Value().data(), dntp.Value().size());
            mDefaultNtp.SetNonNull(MutableByteSpan(mDefaultNtpBuf, dntp.Value().size()));
            return mTimeSyncDataProvider.StoreDefaultNtp(mDefaultNtp.Value());
        }
        else
        {
            mDefaultNtp.SetNull();
            return mTimeSyncDataProvider.ClearDefaultNtp();
        }
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR SetTimeZone(DataModel::DecodableList<TimeSynchronization::Structs::TimeZoneStruct::Type> tz)
    {
        auto mTzL = mTimeZoneList.begin();
        auto tzL  = tz.begin();
        size_t i  = 0;

        while (tzL.Next())
        {
            mTzL[i].offset  = tzL.GetValue().offset;
            mTzL[i].validAt = tzL.GetValue().validAt;
            if (tzL.GetValue().name.HasValue())
            {
                const char * buf = tzL.GetValue().name.Value().data();
                size_t len       = tzL.GetValue().name.Value().size();
                Platform::CopyString(mNames[i].name, chip::CharSpan(buf, len));
            }
            i++;
        }

        return mTimeSyncDataProvider.StoreTimeZone(mTimeZoneList);
    }

    CHIP_ERROR SetDSTOffset(DataModel::DecodableList<TimeSynchronization::Structs::DSTOffsetStruct::Type> dst)
    {
        auto mDstL = mDstOffList.begin();
        auto dstL  = dst.begin();
        size_t i   = 0;

        while (dstL.Next())
        {
            mDstL[i] = dstL.GetValue();
            i++;
        }

        return mTimeSyncDataProvider.StoreDSTOffset(mDstOffList);
    }

    CHIP_ERROR ClearDSTOffset()
    {
        for (size_t i = 0; i < CHIP_CONFIG_DST_OFFSET_LIST_MAX_SIZE; i++)
        {
            mDst[i] = { 0 };
        }

        return mTimeSyncDataProvider.ClearDSTOffset();
    }

    DataModel::Nullable<TimeSynchronization::Structs::TrustedTimeSourceStruct::Type> & GetTrustedTimeSource(void)
    {
        return mTrustedTimeSource;
    }
    DataModel::Nullable<chip::MutableByteSpan> & GetDefaultNtp(void) { return mDefaultNtp; }
    DataModel::List<TimeSynchronization::Structs::TimeZoneStruct::Type> & GetTimeZone(void) { return mTimeZoneList; }
    DataModel::List<TimeSynchronization::Structs::DSTOffsetStruct::Type> & GetDSTOffset(void) { return mDstOffList; }

    void ScheduleDelayedAction(System::Clock::Seconds32 delay, System::TimerCompleteCallback action, void * aAppState);

private:
    DataModel::Nullable<TimeSynchronization::Structs::TrustedTimeSourceStruct::Type> mTrustedTimeSource;
    DataModel::Nullable<chip::MutableByteSpan> mDefaultNtp;
    DataModel::List<TimeSynchronization::Structs::TimeZoneStruct::Type> mTimeZoneList =
        DataModel::List<TimeSynchronization::Structs::TimeZoneStruct::Type>(mTz, CHIP_CONFIG_TIME_ZONE_LIST_MAX_SIZE);
    DataModel::List<TimeSynchronization::Structs::DSTOffsetStruct::Type> mDstOffList =
        DataModel::List<TimeSynchronization::Structs::DSTOffsetStruct::Type>(mDst, CHIP_CONFIG_DST_OFFSET_LIST_MAX_SIZE);

    TimeSynchronization::Structs::TimeZoneStruct::Type mTz[CHIP_CONFIG_TIME_ZONE_LIST_MAX_SIZE];
    struct timeZoneName mNames[CHIP_CONFIG_TIME_ZONE_LIST_MAX_SIZE];
    TimeSynchronization::Structs::DSTOffsetStruct::Type mDst[CHIP_CONFIG_DST_OFFSET_LIST_MAX_SIZE];
    uint8_t mDefaultNtpBuf[DefaultNTP::TypeInfo::MaxLength()];

    TimeSyncDataProvider mTimeSyncDataProvider;
    static TimeSynchronizationServer mTimeSyncInstance;
};

} // namespace TimeSynchronization
} // namespace Clusters
} // namespace app
} // namespace chip
