/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/engine_response_record.hpp"

using namespace shared_model::interface::types;
using namespace shared_model::plain;

EngineReceipt::EngineReceipt(
    shared_model::interface::types::CommandIndexType cmd_index,
    shared_model::interface::types::AccountIdType const &caller,
    shared_model::interface::EngineReceipt::PayloadType payload_type,
    shared_model::interface::types::EvmAddressHexString const &payload,
    std::optional<shared_model::interface::types::EvmDataHexString> const &e_response
    )
    : cmd_index_(cmd_index)
    , caller_(caller)
    , payload_type_(payload_type)
    , payload_(payload)
    , e_response_(e_response)
    { }

shared_model::interface::types::AccountIdType  EngineReceipt::getCaller() const {
    return caller_;
}

shared_model::interface::EngineReceipt::PayloadType  EngineReceipt::getPayloadType() const {
    return payload_type_;
}

int32_t EngineReceipt::getCommandIndex() const {
    return cmd_index_;
}

shared_model::interface::types::EvmAddressHexString const &EngineReceipt::getPayload() const {
    return payload_;
}

shared_model::interface::EngineReceipt::EngineLogsCollectionType const &EngineReceipt::getEngineLogs() const {
    return engine_logs_;
}

shared_model::interface::EngineReceipt::EngineLogsCollectionType &EngineReceipt::getMutableLogs() {
    return engine_logs_;
}

std::optional<shared_model::interface::types::EvmDataHexString> const &EngineReceipt::getResponseData() const {
    return e_response_;
}
