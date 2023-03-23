/*
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

#include "time-synchronization-server.h"
#include "TimeSyncManager.h"
#include "time-synchronization-delegate.h"

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app-common/zap-generated/cluster-objects.h>
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/AttributeAccessInterface.h>
#include <app/CommandHandler.h>
#include <app/EventLogging.h>
#include <app/server/Server.h>
#include <app/util/attribute-storage.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>

#include <app-common/zap-generated/cluster-enums.h>

#include <system/SystemClock.h>

using namespace chip;
using namespace chip::DeviceLayer;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::TimeSynchronization;
using namespace chip::app::Clusters::TimeSynchronization::Attributes;
using chip::TimeSyncDataProvider;
using chip::Protocols::InteractionModel::Status;

// -----------------------------------------------------------------------------
// Delegate Implementation

using chip::app::Clusters::TimeSynchronization::Delegate;

namespace {

Delegate * gDelegate = nullptr;

Delegate * GetDelegate()
{
    if (gDelegate == nullptr)
    {
        static TimeSyncManager dg;
        gDelegate = &dg;
    }
    return gDelegate;
}
} // namespace

namespace chip {
namespace app {
namespace Clusters {
namespace TimeSynchronization {

void SetDefaultDelegate(Delegate * delegate)
{
    gDelegate = delegate;
}

Delegate * GetDefaultDelegate(void)
{
    return GetDelegate();
}

} // namespace TimeSynchronization
} // namespace Clusters
} // namespace app
} // namespace chip

TimeSynchronizationServer TimeSynchronizationServer::mTimeSyncInstance;

TimeSynchronizationServer & TimeSynchronizationServer::Instance(void)
{
    return mTimeSyncInstance;
}

void TimeSynchronizationServer::Init()
{
    TimeSynchronization::Structs::TrustedTimeSourceStruct::Type tts;
    chip::MutableByteSpan mutableDntp(mDefaultNtpBuf);

    mTimeSyncDataProvider.Init(Server::GetInstance().GetPersistentStorage());

    (CHIP_NO_ERROR == mTimeSyncDataProvider.LoadTrustedTimeSource(tts)) ? (void) mTrustedTimeSource.SetNonNull(tts)
                                                                        : mTrustedTimeSource.SetNull();
    (CHIP_NO_ERROR == mTimeSyncDataProvider.LoadDefaultNtp(mutableDntp)) ? (void) mDefaultNtp.SetNonNull(mutableDntp)
                                                                         : mDefaultNtp.SetNull();

    auto tz = mTimeZoneList.begin();
    for (size_t i = 0; i < mTimeZoneList.size(); i++)
    {
        const char * buf = reinterpret_cast<const char *>(mNames[i].name);
        tz[i].name.SetValue(chip::CharSpan(buf, sizeof(mNames[i].name)));
    }
    mTimeSyncDataProvider.LoadTimeZone(mTimeZoneList);
    mTimeSyncDataProvider.LoadDSTOffset(mDstOffList);
    // TODO if trusted time source is available schedule a time read
    if (!mTrustedTimeSource.IsNull())
    {
    }
}

void TimeSynchronizationServer::ScheduleDelayedAction(System::Clock::Seconds32 delay, System::TimerCompleteCallback action,
                                                      void * aAppState)
{
    VerifyOrDie(SystemLayer().StartTimer(std::chrono::duration_cast<System::Clock::Timeout>(delay), action, aAppState) ==
                CHIP_NO_ERROR);
}

namespace {

struct TimeZoneCodec
{
    static constexpr TLV::Tag TagOffset() { return TLV::ContextTag(TimeSynchronization::Structs::TimeZoneStruct::Fields::kOffset); }
    static constexpr TLV::Tag TagValidAt()
    {
        return TLV::ContextTag(TimeSynchronization::Structs::TimeZoneStruct::Fields::kValidAt);
    }
    static constexpr TLV::Tag TagName() { return TLV::ContextTag(TimeSynchronization::Structs::TimeZoneStruct::Fields::kName); }

    TimeSynchronization::Structs::TimeZoneStruct::Type timeZone;

    TimeZoneCodec(TimeSynchronization::Structs::TimeZoneStruct::Type tz) : timeZone(tz) {}

    static constexpr bool kIsFabricScoped = false;

    CHIP_ERROR Encode(TLV::TLVWriter & writer, TLV::Tag tag) const
    {
        TLV::TLVType outer;
        ReturnErrorOnFailure(writer.StartContainer(tag, TLV::kTLVType_Structure, outer));

        // Offset
        ReturnErrorOnFailure(DataModel::Encode(writer, TagOffset(), timeZone.offset));
        // ValidAt
        ReturnErrorOnFailure(DataModel::Encode(writer, TagValidAt(), timeZone.validAt));
        // Name
        if (timeZone.name.HasValue())
        {
            uint32_t name_size = static_cast<uint32_t>(strnlen(timeZone.name.Value().data(), 64));
            ReturnErrorOnFailure(writer.PutString(TagName(), timeZone.name.Value().data(), name_size));
            ChipLogProgress(Zcl, "%s %d", timeZone.name.Value().data(), name_size);
        }
        ReturnErrorOnFailure(writer.EndContainer(outer));
        return CHIP_NO_ERROR;
    }
};

static bool computeLocalTime(chip::EndpointId ep)
{
    DataModel::Nullable<uint64_t> utcTime, localTime;
    int32_t timeZoneOffset = 0, dstOffset = 0;
    UTCTime::Get(ep, utcTime);
    if (utcTime.IsNull())
    {
        return false;
    }
    auto tz  = TimeSynchronizationServer::Instance().GetTimeZone().begin();
    auto dst = TimeSynchronizationServer::Instance().GetDSTOffset().begin();
    if (tz->validAt <= utcTime.Value())
    {
        timeZoneOffset = tz->offset;
    }
    if (dst->validStarting <= utcTime.Value() && dst->offset != 0 && !dst->validUntil.IsNull())
    {
        dstOffset = dst->offset;
    }
    localTime.SetNonNull(utcTime.Value() + static_cast<uint64_t>(timeZoneOffset) + static_cast<uint64_t>(dstOffset));
    LocalTime::Set(ep, localTime);
    return true;
}

class TimeSynchronizationAttrAccess : public AttributeAccessInterface
{
public:
    // Register for the TimeSync cluster on all endpoints
    TimeSynchronizationAttrAccess() : AttributeAccessInterface(Optional<EndpointId>::Missing(), TimeSynchronization::Id) {}

    CHIP_ERROR Read(const ConcreteReadAttributePath & aPath, AttributeValueEncoder & aEncoder) override;

private:
    CHIP_ERROR ReadTrustedTimeSource(EndpointId endpoint, AttributeValueEncoder & aEncoder);
    CHIP_ERROR ReadDefaultNtp(EndpointId endpoint, AttributeValueEncoder & aEncoder);
    CHIP_ERROR ReadTimeZone(EndpointId endpoint, AttributeValueEncoder & aEncoder);
    CHIP_ERROR ReadDSTOffset(EndpointId endpoint, AttributeValueEncoder & aEncoder);
};

TimeSynchronizationAttrAccess gAttrAccess;

CHIP_ERROR TimeSynchronizationAttrAccess::ReadTrustedTimeSource(EndpointId endpoint, AttributeValueEncoder & aEncoder)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    auto tts       = TimeSynchronizationServer::Instance().GetTrustedTimeSource();
    if (!tts.IsNull())
    {
        err = aEncoder.Encode(tts.Value());
    }
    else
    {
        err = aEncoder.EncodeNull();
    }

    return err;
}

CHIP_ERROR TimeSynchronizationAttrAccess::ReadDefaultNtp(EndpointId endpoint, AttributeValueEncoder & aEncoder)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    auto dntp      = TimeSynchronizationServer::Instance().GetDefaultNtp();
    if (!dntp.IsNull())
    {
        const char * buf = reinterpret_cast<const char *>(dntp.Value().data());
        err              = aEncoder.Encode(chip::CharSpan(buf, strnlen(buf, dntp.Value().size())));
    }
    else
    {
        err = aEncoder.EncodeNull();
    }

    return err;
}

CHIP_ERROR TimeSynchronizationAttrAccess::ReadTimeZone(EndpointId endpoint, AttributeValueEncoder & aEncoder)
{
    CHIP_ERROR err = aEncoder.EncodeList([](const auto & encoder) -> CHIP_ERROR {
        DataModel::List<TimeSynchronization::Structs::TimeZoneStruct::Type> tzList =
            TimeSynchronizationServer::Instance().GetTimeZone();
        for (auto it = tzList.begin(); it != tzList.end(); ++it)
        {
            ReturnErrorOnFailure(encoder.Encode(TimeZoneCodec(*it)));
        }

        return CHIP_NO_ERROR;
    });

    return err;
}

CHIP_ERROR TimeSynchronizationAttrAccess::ReadDSTOffset(EndpointId endpoint, AttributeValueEncoder & aEncoder)
{
    CHIP_ERROR err = aEncoder.EncodeList([](const auto & encoder) -> CHIP_ERROR {
        DataModel::List<TimeSynchronization::Structs::DSTOffsetStruct::Type> dst =
            TimeSynchronizationServer::Instance().GetDSTOffset();
        for (auto it = dst.begin(); it != dst.end(); ++it)
        {
            ReturnErrorOnFailure(encoder.Encode(*it));
        }

        return CHIP_NO_ERROR;
    });

    return err;
}

CHIP_ERROR TimeSynchronizationAttrAccess::Read(const ConcreteReadAttributePath & aPath, AttributeValueEncoder & aEncoder)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    if (aPath.mClusterId != TimeSynchronization::Id)
    {
        return CHIP_ERROR_INVALID_PATH_LIST;
    }

    switch (aPath.mAttributeId)
    {
    case UTCTime::Id: {
        DataModel::Nullable<uint64_t> currentUtcTime;
        UTCTime::Get(aPath.mEndpointId, currentUtcTime);
        if (!currentUtcTime.IsNull())
        {
            System::Clock::Microseconds64 utcTime;
            System::SystemClock().GetClock_RealTime(utcTime);
            UTCTime::Set(aPath.mEndpointId, utcTime.count());
            return aEncoder.Encode(utcTime.count());
        }
        else
        {
            return aEncoder.EncodeNull();
        }
    }
    case TrustedTimeSource::Id: {
        return ReadTrustedTimeSource(aPath.mEndpointId, aEncoder);
    }
    case DefaultNTP::Id: {
        return ReadDefaultNtp(aPath.mEndpointId, aEncoder);
    }
    case TimeZone::Id: {
        return ReadTimeZone(aPath.mEndpointId, aEncoder);
    }
    case DSTOffset::Id: {
        return ReadDSTOffset(aPath.mEndpointId, aEncoder);
    }
    case TimeZoneListMaxSize::Id: { // can't find a way to initialize default value for F quality
        uint8_t max = CHIP_CONFIG_TIME_ZONE_LIST_MAX_SIZE;
        TimeZoneListMaxSize::Set(aPath.mEndpointId, CHIP_CONFIG_TIME_ZONE_LIST_MAX_SIZE);
        return aEncoder.Encode(max);
    }
    case DSTOffsetListMaxSize::Id: {
        uint8_t max = CHIP_CONFIG_DST_OFFSET_LIST_MAX_SIZE;
        DSTOffsetListMaxSize::Set(aPath.mEndpointId, CHIP_CONFIG_DST_OFFSET_LIST_MAX_SIZE);
        return aEncoder.Encode(max);
    }
    case LocalTime::Id: {
        DataModel::Nullable<uint64_t> localTime;
        if (computeLocalTime(aPath.mEndpointId))
        {
            LocalTime::Get(aPath.mEndpointId, localTime);
            return aEncoder.Encode(localTime.Value());
        }
        else
        {
            return aEncoder.EncodeNull();
        }
    }
    default: {
        break;
    }
    }

    return err;
}
} // anonymous namespace

static bool sendDSTTableEmpty(chip::EndpointId endpointId)
{
    Events::DSTTableEmpty::Type event;
    EventNumber eventNumber;

    CHIP_ERROR error = LogEvent(event, endpointId, eventNumber);

    if (CHIP_NO_ERROR != error)
    {
        ChipLogError(Zcl, "Unable to send DSTTableEmpty event [endpointId=%d]", endpointId);
        return false;
    }
    ChipLogProgress(Zcl, "Emit DSTTableEmpty event [endpointId=%d]", endpointId);

    // re-schedule event for after min 1hr
    // delegate->scheduleDSTTableEmptyEvent()
    return true;
}

static bool sendDSTStatus(chip::EndpointId endpointId, bool dstOffsetActive)
{
    Events::DSTStatus::Type event;
    event.DSTOffsetActive = dstOffsetActive;
    EventNumber eventNumber;

    CHIP_ERROR error = LogEvent(event, endpointId, eventNumber);

    if (CHIP_NO_ERROR != error)
    {
        ChipLogError(Zcl, "Unable to send sendDSTStatus event [endpointId=%d]", endpointId);
        return false;
    }

    ChipLogProgress(Zcl, "Emit sendDSTStatus event [endpointId=%d]", endpointId);
    return true;
}

static bool sendTimeZoneStatus(chip::EndpointId endpointId, uint8_t listIndex)
{
    Events::TimeZoneStatus::Type event;
    auto tz      = TimeSynchronizationServer::Instance().GetTimeZone().begin();
    event.offset = tz[listIndex].offset;
    if (tz[listIndex].name.HasValue())
    {
        event.name = tz[listIndex].name.Value();
    }
    EventNumber eventNumber;

    CHIP_ERROR error = LogEvent(event, endpointId, eventNumber);

    if (CHIP_NO_ERROR != error)
    {
        ChipLogError(Zcl, "Unable to send sendTimeZoneStatus event [endpointId=%d]", endpointId);
        return false;
    }

    ChipLogProgress(Zcl, "Emit sendTimeZoneStatus event [endpointId=%d]", endpointId);
    return true;
}

static bool sendTimeFailure(chip::EndpointId endpointId)
{
    Events::TimeFailure::Type event;
    EventNumber eventNumber;

    CHIP_ERROR error = LogEvent(event, endpointId, eventNumber);

    if (CHIP_NO_ERROR != error)
    {
        ChipLogError(Zcl, "Unable to send sendTimeFailure event [endpointId=%d]", endpointId);
        return false;
    }

    // re-schedule event for after min 1hr if no time is still available
    ChipLogProgress(Zcl, "Emit sendTimeFailure event [endpointId=%d]", endpointId);
    return true;
}

static bool sendMissingTrustedTimeSource(chip::EndpointId endpointId)
{
    Events::MissingTrustedTimeSource::Type event;
    EventNumber eventNumber;

    CHIP_ERROR error = LogEvent(event, endpointId, eventNumber);

    if (CHIP_NO_ERROR != error)
    {
        ChipLogError(Zcl, "Unable to send sendMissingTrustedTimeSource event [endpointId=%d]", endpointId);
        return false;
    }

    // re-schedule event for after min 1hr if TTS is null or cannot be reached
    ChipLogProgress(Zcl, "Emit sendMissingTrustedTimeSource event [endpointId=%d]", endpointId);
    return true;
}

static void utcTimeChanged(uint64_t utcTime)
{
    System::Clock::Seconds32 lastKnownGoodChipEpoch;
    System::Clock::Microseconds64 realTime;
    uint32_t utcTimetoChipEpoch;

    Server::GetInstance().GetFabricTable().GetLastKnownGoodChipEpochTime(lastKnownGoodChipEpoch);
    System::SystemClock().GetClock_RealTime(realTime);
    ChipLogError(Zcl, "UTCTime: %llu Last Known Good Time: %u Real Time: %llu", utcTime, lastKnownGoodChipEpoch.count(),
                 realTime.count());
    chip::UnixEpochToChipEpochTime((uint32_t)(utcTime / chip::kMicrosecondsPerSecond), utcTimetoChipEpoch);

    if (utcTimetoChipEpoch >= lastKnownGoodChipEpoch.count()) // update Last Known Good Time if a more recent time is obtained
    {
        Server::GetInstance().GetFabricTable().SetLastKnownGoodChipEpochTime(System::Clock::Seconds32(utcTimetoChipEpoch));
        System::SystemClock().SetClock_RealTime(System::Clock::Microseconds64(utcTime));

        Server::GetInstance().GetFabricTable().GetLastKnownGoodChipEpochTime(lastKnownGoodChipEpoch);
        System::SystemClock().GetClock_RealTime(realTime);
        ChipLogError(Zcl, " Last Known Good Time: %u Real Time: %llu", lastKnownGoodChipEpoch.count(), realTime.count());
    }
}

bool emberAfTimeSynchronizationClusterSetUtcTimeCallback(
    chip::app::CommandHandler * commandObj, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::TimeSynchronization::Commands::SetUtcTime::DecodableType & commandData)
{
    Optional<StatusCode> status = Optional<StatusCode>::Missing();
    Status globalStatus         = Status::Success;

    auto utcTime     = commandData.utcTime;
    auto granularity = commandData.granularity;
    auto timeSource  = commandData.timeSource;

    TimeSynchronization::GranularityEnum currentGranularity;
    Granularity::Get(commandPath.mEndpointId, &currentGranularity);

    if (currentGranularity == TimeSynchronization::GranularityEnum::kNoTimeGranularity || granularity >= currentGranularity)
    {
        UTCTime::Set(commandPath.mEndpointId, utcTime);
        utcTimeChanged(utcTime);
        Granularity::Set(commandPath.mEndpointId, granularity);
        if (timeSource.HasValue())
        {
            TimeSource::Set(commandPath.mEndpointId, timeSource.Value());
        }
        else
        {
            TimeSource::Set(commandPath.mEndpointId, TimeSynchronization::TimeSourceEnum::kAdmin);
        }
    }
    else
    {
        status.Emplace(TimeSynchronization::StatusCode::kTimeNotAccepted);
    }

    if (status.HasValue())
    {
        commandObj->AddClusterSpecificFailure(commandPath, to_underlying(status.Value()));
    }
    else
    {
        commandObj->AddStatus(commandPath, globalStatus);
    }
    return true;
}

bool emberAfTimeSynchronizationClusterSetTrustedTimeSourceCallback(
    chip::app::CommandHandler * commandObj, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::TimeSynchronization::Commands::SetTrustedTimeSource::DecodableType & commandData)
{
    Status status   = Status::Success;
    auto timeSource = commandData.trustedTimeSource;
    DataModel::Nullable<TimeSynchronization::Structs::TrustedTimeSourceStruct::Type> tts;

    if (!timeSource.IsNull())
    {

        TimeSynchronization::Structs::TrustedTimeSourceStruct::Type ts = { commandObj->GetAccessingFabricIndex(),
                                                                           timeSource.Value().nodeID, timeSource.Value().endpoint };
        tts.SetNonNull(ts);
        // TODO schedule a utctime read from this time source
    }
    else
    {
        tts.SetNull();
        sendMissingTrustedTimeSource(commandPath.mEndpointId);
    }

    TimeSynchronizationServer::Instance().SetTrustedTimeSource(tts);
    commandObj->AddStatus(commandPath, status);
    return true;
}

bool emberAfTimeSynchronizationClusterSetTimeZoneCallback(
    chip::app::CommandHandler * commandObj, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::TimeSynchronization::Commands::SetTimeZone::DecodableType & commandData)
{
    auto timeZone = commandData.timeZone;
    size_t items;
    uint8_t maxSize = 0;
    timeZone.ComputeSize(&items);
    TimeZoneListMaxSize::Get(commandPath.mEndpointId, &maxSize);

    if (items > maxSize || items > CHIP_CONFIG_TIME_ZONE_LIST_MAX_SIZE)
    {
        commandObj->AddStatus(commandPath, Status::ResourceExhausted);
        return true;
    }
    // first element shall have validAt entry of 0
    // if second element, it shall have validAt entry of non-0

    if (CHIP_NO_ERROR != TimeSynchronizationServer::Instance().SetTimeZone(timeZone))
    {
        commandObj->AddStatus(commandPath, Status::ConstraintError);
        return true;
    }
    sendTimeZoneStatus(commandPath.mEndpointId, 0);
    sendTimeFailure(commandPath.mEndpointId); // TODO remove
    GetDelegate()->HandleTimeZoneChanged(TimeSynchronizationServer::Instance().GetTimeZone());
    GetDelegate()->HandleDstoffsetlookup();

    TimeSynchronization::TimeZoneDatabaseEnum tzDb;
    TimeZoneDatabase::Get(commandPath.mEndpointId, &tzDb);
    if (GetDelegate()->HasFeature(0, TimeSynchronization::TimeSynchronizationFeature::kTimeZone) &&
        tzDb != TimeSynchronization::TimeZoneDatabaseEnum::kNone)
    {
        auto tz = TimeSynchronizationServer::Instance().GetTimeZone().begin();
        Commands::SetTimeZoneResponse::Type response;
        if (GetDelegate()->HandleDstoffsetavailable(tz->name.Value()) == true)
        {
            GetDelegate()->HandleGetdstoffset();
            response.DSTOffsetRequired = false;
            sendDSTStatus(commandPath.mEndpointId, true);
        }
        else
        {
            TimeSynchronizationServer::Instance().ClearDSTOffset();
            sendDSTTableEmpty(commandPath.mEndpointId);
            response.DSTOffsetRequired = true;
            sendDSTStatus(commandPath.mEndpointId, false);
        }
        commandObj->AddResponse(commandPath, response);
        computeLocalTime(commandPath.mEndpointId);
        return true;
    }

    computeLocalTime(commandPath.mEndpointId);

    commandObj->AddStatus(commandPath, Status::Success);

    return true;
}

bool emberAfTimeSynchronizationClusterSetDSTOffsetCallback(
    chip::app::CommandHandler * commandObj, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::TimeSynchronization::Commands::SetDSTOffset::DecodableType & commandData)
{
    Status status  = Status::Success;
    auto dstOffset = commandData.DSTOffset;
    size_t items;
    uint8_t maxSize = 0;
    dstOffset.ComputeSize(&items);
    DSTOffsetListMaxSize::Get(commandPath.mEndpointId, &maxSize);

    if (items > maxSize && items > CHIP_CONFIG_DST_OFFSET_LIST_MAX_SIZE)
    {
        commandObj->AddStatus(commandPath, Status::ResourceExhausted);
        return true;
    }

    // sorted by ValidStarting time
    // ValidStartingTime shall not be smaller than ValidUntil time of previous entry
    // only 1 validuntil null value and shall be last in the list
    // remove entries which are no longer active
    // if offset == 0 && ValidUntil == null then no DST is used
    if (CHIP_NO_ERROR != TimeSynchronizationServer::Instance().SetDSTOffset(dstOffset))
    {
        commandObj->AddStatus(commandPath, Status::ConstraintError);
        return true;
    }
    // if DST state changes, generate DSTStatus event
    sendDSTStatus(commandPath.mEndpointId, true);
    // if list is empty, generate DSTTableEmpty event
    sendDSTTableEmpty(commandPath.mEndpointId);

    commandObj->AddStatus(commandPath, status);
    return true;
}

bool emberAfTimeSynchronizationClusterSetDefaultNTPCallback(
    chip::app::CommandHandler * commandObj, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::TimeSynchronization::Commands::SetDefaultNTP::DecodableType & commandData)
{
    Status status = Status::Success;
    auto dntpChar = commandData.defaultNTP;
    DataModel::Nullable<chip::MutableByteSpan> dntpByte;

    if (!dntpChar.IsNull())
    {
        if (!GetDelegate()->isNTPAddressValid(dntpChar.Value()))
        {
            commandObj->AddStatus(commandPath, Status::InvalidCommand);
            return true;
        }
        if (GetDelegate()->isNTPAddressDomain(dntpChar.Value()))
        {
            bool dnsResolve;
            SupportsDNSResolve::Get(commandPath.mEndpointId, &dnsResolve);
            if (!dnsResolve)
            {
                commandObj->AddStatus(commandPath, Status::InvalidCommand);
                return true;
            }
        }

        uint8_t buffer[DefaultNTP::TypeInfo::MaxLength()];
        chip::MutableByteSpan dntp(buffer);
        size_t len = (dntpChar.Value().size() < dntp.size()) ? dntpChar.Value().size() : dntp.size();
        memcpy(buffer, dntpChar.Value().data(), len);

        dntp = MutableByteSpan(dntp.data(), len);
        dntpByte.SetNonNull(dntp);
    }
    else
    {
        dntpByte.SetNull();
    }
    status =
        (CHIP_NO_ERROR == TimeSynchronizationServer::Instance().SetDefaultNtp(dntpByte)) ? Status::Success : Status::InvalidCommand;

    commandObj->AddStatus(commandPath, status);
    return true;
}

void MatterTimeSynchronizationPluginServerInitCallback()
{
    static bool attrAccessRegistered = false;
    TimeSynchronizationServer::Instance().Init();
    if (!attrAccessRegistered)
    {
        attrAccessRegistered = true;
        registerAttributeAccessOverride(&gAttrAccess);
#if 0
        TimeSynchronization::GranularityEnum granularity = TimeSynchronization::GranularityEnum::kNoTimeGranularity;
        TimeSynchronization::Attributes::Granularity::Set(0, granularity);
        // System::SystemClock().SetClock_RealTime(System::Clock::Microseconds64(1679668000000000));
#endif
    }
}
