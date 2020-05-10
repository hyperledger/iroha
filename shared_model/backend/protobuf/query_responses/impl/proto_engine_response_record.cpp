/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_engine_response_record.hpp"

#include <boost/optional.hpp>
#include <boost/range/adaptor/transformed.hpp>

#include "backend/protobuf/query_responses/proto_engine_log.hpp"

using namespace shared_model::proto;

EngineReceipt::EngineReceipt(const TransportType &proto)
    : proto_(proto)
    , response_data_((proto.has_call_result() && !proto.call_result().result_data().empty()) ?
            std::optional<shared_model::interface::types::EvmDataHexString>(proto.call_result().result_data()) :
            std::nullopt)
    {
        engine_logs_.reserve(proto_.logs().size());
        for (auto const &log : proto_.logs()) {
            engine_logs_.emplace_back(std::make_unique<shared_model::proto::EngineLog>(log));
        }
    }

EngineReceipt::EngineReceipt(const EngineReceipt &o)
    : EngineReceipt(o.proto_) {}

shared_model::interface::types::AccountIdType EngineReceipt::getCaller() const {
    return proto_.caller();
}

shared_model::interface::EngineReceipt::PayloadType EngineReceipt::getPayloadType() const {
    if (proto_.opt_to_contract_address_case() == iroha::protocol::EngineReceipt::kCallResult)
        return shared_model::interface::EngineReceipt::PayloadType::kPayloadTypeCallResult;
    else if (proto_.opt_to_contract_address_case() == iroha::protocol::EngineReceipt::kContractAddress)
        return shared_model::interface::EngineReceipt::PayloadType::kPayloadTypeContractAddress;
    else
        return shared_model::interface::EngineReceipt::PayloadType::kPayloadTypeUnk;
}

int32_t EngineReceipt::getCommandIndex() const {
    return proto_.command_index();
}

shared_model::interface::types::EvmAddressHexString const &EngineReceipt::getPayload() const {
    if (proto_.opt_to_contract_address_case() == iroha::protocol::EngineReceipt::kCallResult) {
        return proto_.call_result().callee();
    } else if (proto_.opt_to_contract_address_case() == iroha::protocol::EngineReceipt::kContractAddress) {
        return proto_.contract_address();
    } else {
        assert(!"Unexpected call. Check payload type.");
        static shared_model::interface::types::EvmAddressHexString _;
        return _;
    }
}

shared_model::interface::EngineReceipt::EngineLogsCollectionType const &EngineReceipt::getEngineLogs() const {
    return engine_logs_;
}

std::optional<shared_model::interface::types::EvmDataHexString> const &EngineReceipt::getResponseData() const {
    return response_data_;
}
