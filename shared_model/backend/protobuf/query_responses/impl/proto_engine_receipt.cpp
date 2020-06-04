/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_engine_receipt.hpp"

#include <boost/optional.hpp>
#include <boost/range/adaptor/transformed.hpp>

#include "backend/protobuf/query_responses/proto_engine_log.hpp"

using namespace shared_model::proto;

EngineReceipt::EngineReceipt(const TransportType &proto)
    : proto_(proto),
      response_data_(
          (proto.has_call_result()
           && !proto.call_result().result_data().empty())
              ? std::optional<shared_model::interface::types::EvmDataHexString>(
                    proto.call_result().result_data())
              : std::nullopt),
      call_result_(
          proto.has_call_result()
              ? std::optional<
                    shared_model::interface::EngineReceipt::CallResult>(
                    {proto.call_result().callee(), response_data_})
              : std::nullopt),
      contact_address_(
          proto.result_or_contract_address_case()
                  == iroha::protocol::EngineReceipt::kContractAddress
              ? std::optional<
                    shared_model::interface::types::EvmAddressHexString>(
                    proto.contract_address())
              : std::nullopt) {
  static_assert(offsetof(EngineReceipt, response_data_)
                    < offsetof(EngineReceipt, call_result_),
                "Check ctor");

  engine_logs_.reserve(proto_.logs().size());
  for (auto const &log : proto_.logs()) {
    engine_logs_.emplace_back(
        std::make_unique<shared_model::proto::EngineLog>(log));
  }
}

EngineReceipt::EngineReceipt(const EngineReceipt &o)
    : EngineReceipt(o.proto_) {}

shared_model::interface::types::AccountIdType EngineReceipt::getCaller() const {
  return proto_.caller();
}

shared_model::interface::EngineReceipt::PayloadType
EngineReceipt::getPayloadType() const {
  if (proto_.result_or_contract_address_case()
      == iroha::protocol::EngineReceipt::kCallResult)
    return shared_model::interface::EngineReceipt::PayloadType::
        kPayloadTypeCallResult;
  else if (proto_.result_or_contract_address_case()
           == iroha::protocol::EngineReceipt::kContractAddress)
    return shared_model::interface::EngineReceipt::PayloadType::
        kPayloadTypeContractAddress;
  else
    return shared_model::interface::EngineReceipt::PayloadType::kPayloadTypeUnk;
}

int32_t EngineReceipt::getCommandIndex() const {
  return proto_.command_index();
}

std::optional<shared_model::interface::EngineReceipt::CallResult> const &
EngineReceipt::getResponseData() const {
  return call_result_;
}

std::optional<shared_model::interface::types::EvmAddressHexString> const &
EngineReceipt::getContractAddress() const {
  return contact_address_;
}

shared_model::interface::EngineReceipt::EngineLogsCollectionType const &
EngineReceipt::getEngineLogs() const {
  return engine_logs_;
}
